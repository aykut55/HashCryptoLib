#include "CertificateManager.h"
#include "Definitions/Definitions.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <wincrypt.h>
#ifdef NO_ERROR
#undef NO_ERROR
#endif

#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace CryptoApiNS
{

namespace
{

// ================================================================================================
// RAII wrappers for OpenSSL's own C-allocated types, kept local to this translation unit --
// exactly the reasoning CertificateManager.h's own comment gives for hiding OpenSSL/Crypt32 types
// from the public header (same pattern as CPgpEngine hiding CryptoPP behind Impl).
// ================================================================================================

struct X509Deleter        { void operator()(X509* p)              const { if (p) X509_free(p); } };
struct X509CrlDeleter      { void operator()(X509_CRL* p)          const { if (p) X509_CRL_free(p); } };
struct X509ReqDeleter      { void operator()(X509_REQ* p)          const { if (p) X509_REQ_free(p); } };
struct EvpPkeyDeleter      { void operator()(EVP_PKEY* p)          const { if (p) EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter   { void operator()(EVP_PKEY_CTX* p)      const { if (p) EVP_PKEY_CTX_free(p); } };
struct BioDeleter          { void operator()(BIO* p)               const { if (p) BIO_free(p); } };
struct Pkcs12Deleter       { void operator()(PKCS12* p)            const { if (p) PKCS12_free(p); } };
struct BnDeleter           { void operator()(BIGNUM* p)            const { if (p) BN_free(p); } };
struct Asn1IntegerDeleter  { void operator()(ASN1_INTEGER* p)      const { if (p) ASN1_INTEGER_free(p); } };
struct GeneralNamesDeleter { void operator()(GENERAL_NAMES* p)     const { if (p) GENERAL_NAMES_free(p); } };
struct ExtKeyUsageDeleter  { void operator()(EXTENDED_KEY_USAGE* p) const { if (p) EXTENDED_KEY_USAGE_free(p); } };
struct BitStringDeleter    { void operator()(ASN1_BIT_STRING* p)  const { if (p) ASN1_BIT_STRING_free(p); } };
struct ExtensionDeleter    { void operator()(X509_EXTENSION* p)   const { if (p) X509_EXTENSION_free(p); } };

typedef std::unique_ptr<X509, X509Deleter> X509Ptr;
typedef std::unique_ptr<X509_CRL, X509CrlDeleter> X509CrlPtr;
typedef std::unique_ptr<X509_REQ, X509ReqDeleter> X509ReqPtr;
typedef std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> EvpPkeyPtr;
typedef std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> EvpPkeyCtxPtr;
typedef std::unique_ptr<BIO, BioDeleter> BioPtr;
typedef std::unique_ptr<PKCS12, Pkcs12Deleter> Pkcs12Ptr;
typedef std::unique_ptr<BIGNUM, BnDeleter> BnPtr;
typedef std::unique_ptr<ASN1_INTEGER, Asn1IntegerDeleter> Asn1IntegerPtr;
typedef std::unique_ptr<GENERAL_NAMES, GeneralNamesDeleter> GeneralNamesPtr;
typedef std::unique_ptr<EXTENDED_KEY_USAGE, ExtKeyUsageDeleter> ExtKeyUsagePtr;
typedef std::unique_ptr<ASN1_BIT_STRING, BitStringDeleter> BitStringPtr;
typedef std::unique_ptr<X509_EXTENSION, ExtensionDeleter> ExtensionPtr;

// ================================================================================================
// Buffer-output helpers -- same "capacity query" convention as CPgpEngine::ExportPublicKeyArmored
// (capacity=0/buffer=nullptr queries the required size and returns BUFFER_TOO_SMALL).
// ================================================================================================

int WriteBytesOut(const void* data, const std::size_t dataSize, const int outputCapacity, void* outputBuffer, int* outputSize)
{
    if (outputSize == nullptr)
    {
        return INVALID_ARGUMENT;
    }
    *outputSize = static_cast<int>(dataSize);
    if (outputBuffer == nullptr || outputCapacity < static_cast<int>(dataSize))
    {
        return BUFFER_TOO_SMALL;
    }
    if (dataSize > 0)
    {
        std::memcpy(outputBuffer, data, dataSize);
    }
    return NO_ERROR;
}
// -----------------------------------------------------------------------------

int WriteTextOut(const std::string& text, const int outputCapacity, char* outputBuffer, int* outputSize)
{
    return WriteBytesOut(text.data(), text.size(), outputCapacity, outputBuffer, outputSize);
}
// -----------------------------------------------------------------------------

int WriteDerOut(const std::vector<unsigned char>& der, const int outputCapacity, unsigned char* outputBuffer, int* outputSize)
{
    return WriteBytesOut(der.empty() ? nullptr : der.data(), der.size(), outputCapacity, outputBuffer, outputSize);
}
// -----------------------------------------------------------------------------

// ================================================================================================
// OpenSSL conversion helpers.
// ================================================================================================

X509* DerBufferToX509(const unsigned char* buffer, const int bufferSize)
{
    const unsigned char* p = buffer;
    return d2i_X509(nullptr, &p, bufferSize);
}
// -----------------------------------------------------------------------------

X509_REQ* DerBufferToX509Req(const unsigned char* buffer, const int bufferSize)
{
    const unsigned char* p = buffer;
    return d2i_X509_REQ(nullptr, &p, bufferSize);
}
// -----------------------------------------------------------------------------

bool X509ToDerBuffer(X509* cert, std::vector<unsigned char>& out)
{
    unsigned char* p = nullptr;
    const int len = i2d_X509(cert, &p);
    if (len <= 0 || p == nullptr)
    {
        return false;
    }
    out.assign(p, p + len);
    OPENSSL_free(p);
    return true;
}
// -----------------------------------------------------------------------------

bool X509ReqToDerBuffer(X509_REQ* req, std::vector<unsigned char>& out)
{
    unsigned char* p = nullptr;
    const int len = i2d_X509_REQ(req, &p);
    if (len <= 0 || p == nullptr)
    {
        return false;
    }
    out.assign(p, p + len);
    OPENSSL_free(p);
    return true;
}
// -----------------------------------------------------------------------------

EVP_PKEY* PemBufferToPrivateKey(const char* pem, const int pemSize)
{
    BioPtr bio(BIO_new_mem_buf(pem, pemSize));
    if (!bio)
    {
        return nullptr;
    }
    return PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
}
// -----------------------------------------------------------------------------

bool PrivateKeyToPemString(EVP_PKEY* key, std::string& out)
{
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio)
    {
        return false;
    }
    if (PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        return false;
    }
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    if (len < 0 || data == nullptr)
    {
        return false;
    }
    out.assign(data, static_cast<std::size_t>(len));
    return true;
}
// -----------------------------------------------------------------------------

EVP_PKEY* GenerateKeyPairForAlgorithm(const CertificateKeyAlgorithm algorithm)
{
    if (algorithm == CERTIFICATE_KEY_ECDSA_P256 || algorithm == CERTIFICATE_KEY_ECDSA_P384)
    {
        EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0)
        {
            return nullptr;
        }
        const int curveNid = (algorithm == CERTIFICATE_KEY_ECDSA_P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), curveNid) <= 0)
        {
            return nullptr;
        }
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0)
        {
            return nullptr;
        }
        return pkey;
    }
    else
    {
        int bits = 2048;
        if (algorithm == CERTIFICATE_KEY_RSA_3072) bits = 3072;
        else if (algorithm == CERTIFICATE_KEY_RSA_4096) bits = 4096;

        EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0)
        {
            return nullptr;
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0)
        {
            return nullptr;
        }
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0)
        {
            return nullptr;
        }
        return pkey;
    }
}
// -----------------------------------------------------------------------------

const EVP_MD* CertificateDigestToEvpMd(const CertificateDigestAlgorithm digestAlgorithm)
{
    switch (digestAlgorithm)
    {
    case CERTIFICATE_DIGEST_SHA384: return EVP_sha384();
    case CERTIFICATE_DIGEST_SHA512: return EVP_sha512();
    default:                        return EVP_sha256();
    }
}
// -----------------------------------------------------------------------------

// Splits a comma-separated DNS SAN list into the "DNS:a,DNS:b" form X509V3_EXT_nconf_nid expects.
std::string BuildSanGenConfString(const std::string& sanDnsNamesCsv)
{
    std::string result;
    std::size_t start = 0;
    while (start <= sanDnsNamesCsv.size())
    {
        const std::size_t comma = sanDnsNamesCsv.find(',', start);
        std::string token = sanDnsNamesCsv.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.erase(token.begin());
        while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.pop_back();
        if (!token.empty())
        {
            if (!result.empty()) result += ",";
            result += "DNS:" + token;
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return result;
}
// -----------------------------------------------------------------------------

bool AddSanExtensionToCertificate(X509* cert, const std::string& sanDnsNamesCsv)
{
    if (sanDnsNamesCsv.empty())
    {
        return true;
    }
    const std::string genConfig = BuildSanGenConfString(sanDnsNamesCsv);
    if (genConfig.empty())
    {
        return true;
    }
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    ExtensionPtr ext(X509V3_EXT_nconf_nid(nullptr, &ctx, NID_subject_alt_name, genConfig.c_str()));
    if (!ext)
    {
        return false;
    }
    return X509_add_ext(cert, ext.get(), -1) == 1;
}
// -----------------------------------------------------------------------------

bool AddSanExtensionToRequest(X509_REQ* req, const std::string& sanDnsNamesCsv)
{
    if (sanDnsNamesCsv.empty())
    {
        return true;
    }
    const std::string genConfig = BuildSanGenConfString(sanDnsNamesCsv);
    if (genConfig.empty())
    {
        return true;
    }
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);
    ExtensionPtr ext(X509V3_EXT_nconf_nid(nullptr, &ctx, NID_subject_alt_name, genConfig.c_str()));
    if (!ext)
    {
        return false;
    }
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    if (exts == nullptr)
    {
        return false;
    }
    sk_X509_EXTENSION_push(exts, ext.release());
    const bool ok = X509_REQ_add_extensions(req, exts) == 1;
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return ok;
}
// -----------------------------------------------------------------------------

// Copies the Subject Alternative Name extension (if any) from a parsed CSR's requested-extensions
// attribute onto a certificate being issued from that CSR -- IssueCertificateFromRequest trusts
// whatever SAN the CSR itself asked for rather than re-deriving it, matching real CA behavior.
bool CopySanExtensionFromRequest(X509_REQ* req, X509* cert)
{
    STACK_OF(X509_EXTENSION)* reqExts = X509_REQ_get_extensions(req);
    if (reqExts == nullptr)
    {
        return true;
    }
    bool ok = true;
    const int index = X509v3_get_ext_by_NID(reqExts, NID_subject_alt_name, -1);
    if (index >= 0)
    {
        const X509_EXTENSION* found = X509v3_get_ext(reqExts, index);
        if (found != nullptr)
        {
            ok = X509_add_ext(cert, found, -1) == 1;
        }
    }
    sk_X509_EXTENSION_pop_free(reqExts, X509_EXTENSION_free);
    return ok;
}
// -----------------------------------------------------------------------------

bool SetCertificateValidityPeriod(X509* cert, const int validityDays)
{
    if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == nullptr)
    {
        return false;
    }
    const long validitySeconds = static_cast<long>(validityDays) * 24L * 60L * 60L;
    if (X509_gmtime_adj(X509_getm_notAfter(cert), validitySeconds) == nullptr)
    {
        return false;
    }
    return true;
}
// -----------------------------------------------------------------------------

// keyUsageFlags/extendedKeyUsageFlags are CertificateKeyUsageFlag/CertificateExtendedKeyUsageFlag
// bit combinations (see ICertificateManager.h). Basic Constraints is always written, critical, with
// CA:TRUE only when CERTIFICATE_KEY_USAGE_KEY_CERT_SIGN is set -- otherwise CA:FALSE, matching
// Plan.md 25.5 ("Varsayılan kullanım end-entity'dir; CA yetkisi kendiliğinden verilmez").
bool AddKeyUsageExtensions(X509* cert, const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

    const bool isCa = (keyUsageFlags & CERTIFICATE_KEY_USAGE_KEY_CERT_SIGN) != 0;
    {
        ExtensionPtr ext(X509V3_EXT_nconf_nid(nullptr, &ctx, NID_basic_constraints, isCa ? "critical,CA:TRUE" : "critical,CA:FALSE"));
        if (!ext || X509_add_ext(cert, ext.get(), -1) != 1)
        {
            return false;
        }
    }

    if (keyUsageFlags != 0)
    {
        std::string kuValue;
        if (keyUsageFlags & CERTIFICATE_KEY_USAGE_DIGITAL_SIGNATURE) kuValue += "digitalSignature,";
        if (keyUsageFlags & CERTIFICATE_KEY_USAGE_NON_REPUDIATION)  kuValue += "nonRepudiation,";
        if (keyUsageFlags & CERTIFICATE_KEY_USAGE_KEY_ENCIPHERMENT) kuValue += "keyEncipherment,";
        if (keyUsageFlags & CERTIFICATE_KEY_USAGE_KEY_CERT_SIGN)    kuValue += "keyCertSign,";
        if (keyUsageFlags & CERTIFICATE_KEY_USAGE_CRL_SIGN)         kuValue += "cRLSign,";
        if (!kuValue.empty())
        {
            kuValue.pop_back();
            ExtensionPtr ext(X509V3_EXT_nconf_nid(nullptr, &ctx, NID_key_usage, ("critical," + kuValue).c_str()));
            if (!ext || X509_add_ext(cert, ext.get(), -1) != 1)
            {
                return false;
            }
        }
    }

    if (extendedKeyUsageFlags != 0)
    {
        std::string ekuValue;
        if (extendedKeyUsageFlags & CERTIFICATE_EKU_SERVER_AUTH)      ekuValue += "serverAuth,";
        if (extendedKeyUsageFlags & CERTIFICATE_EKU_CLIENT_AUTH)      ekuValue += "clientAuth,";
        if (extendedKeyUsageFlags & CERTIFICATE_EKU_CODE_SIGNING)     ekuValue += "codeSigning,";
        if (extendedKeyUsageFlags & CERTIFICATE_EKU_EMAIL_PROTECTION) ekuValue += "emailProtection,";
        if (extendedKeyUsageFlags & CERTIFICATE_EKU_TIME_STAMPING)    ekuValue += "timeStamping,";
        if (!ekuValue.empty())
        {
            ekuValue.pop_back();
            ExtensionPtr ext(X509V3_EXT_nconf_nid(nullptr, &ctx, NID_ext_key_usage, ekuValue.c_str()));
            if (!ext || X509_add_ext(cert, ext.get(), -1) != 1)
            {
                return false;
            }
        }
    }

    return true;
}
// -----------------------------------------------------------------------------

std::string X509NameToOnelineString(const X509_NAME* name)
{
    if (name == nullptr)
    {
        return std::string();
    }
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio)
    {
        return std::string();
    }
    X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || data == nullptr)
    {
        return std::string();
    }
    return std::string(data, static_cast<std::size_t>(len));
}
// -----------------------------------------------------------------------------

std::string Asn1TimeToString(const ASN1_TIME* time)
{
    if (time == nullptr)
    {
        return std::string();
    }
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio)
    {
        return std::string();
    }
    ASN1_TIME_print(bio.get(), time);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || data == nullptr)
    {
        return std::string();
    }
    return std::string(data, static_cast<std::size_t>(len));
}
// -----------------------------------------------------------------------------

std::string BytesToHexString(const unsigned char* data, const std::size_t size)
{
    static const char* hexDigits = "0123456789ABCDEF";
    std::string out;
    out.resize(size * 2);
    for (std::size_t i = 0; i < size; ++i)
    {
        out[i * 2]     = hexDigits[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexDigits[data[i] & 0xF];
    }
    return out;
}
// -----------------------------------------------------------------------------

// UTF-8 std::string <-> UTF-16 std::wstring, needed only for the handful of Crypt32 wide-string
// APIs below (CertOpenStore's system-store name, CERT_FIND_SUBJECT_STR, PFXImportCertStore's
// password) -- same conversion direction CryptoApi.cpp's own EncryptFile/DecryptFile use for
// UTF-8 file paths.
std::wstring Utf8ToWide(const char* utf8, const int utf8Size)
{
    if (utf8 == nullptr || utf8Size <= 0)
    {
        return std::wstring();
    }
    const int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8, utf8Size, nullptr, 0);
    if (wideLen <= 0)
    {
        return std::wstring();
    }
    std::wstring wide(static_cast<std::size_t>(wideLen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, utf8Size, &wide[0], wideLen);
    return wide;
}
// -----------------------------------------------------------------------------

} // namespace

struct CCertificateManager::Impl
{
    HCERTSTORE openStore;
    bool storeOpen;
    std::vector<std::vector<unsigned char> > intermediateCerts;

    Impl() : openStore(nullptr), storeOpen(false)
    {
    }
};

CCertificateManager::~CCertificateManager()
{
    try
    {
        if (impl_ && impl_->storeOpen && impl_->openStore != nullptr)
        {
            CertCloseStore(impl_->openStore, 0);
        }
    }
    catch (...)
    {
    }
}
// -----------------------------------------------------------------------------

CCertificateManager::CCertificateManager() : impl_(new Impl())
{
}
// -----------------------------------------------------------------------------

int CCertificateManager::GetCertificateInfoText( const unsigned char* certDerBuffer, const int certDerBufferSize,
                                                 const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const
{
    try
    {
        if (certDerBuffer == nullptr || certDerBufferSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        X509Ptr cert(DerBufferToX509(certDerBuffer, certDerBufferSize));
        if (!cert)
        {
            return INVALID_DATA;
        }

        std::string text;
        text += "Subject: " + X509NameToOnelineString(X509_get_subject_name(cert.get())) + "\n";
        text += "Issuer: " + X509NameToOnelineString(X509_get_issuer_name(cert.get())) + "\n";

        {
            BnPtr serialBn(ASN1_INTEGER_to_BN(X509_get_serialNumber(cert.get()), nullptr));
            if (serialBn)
            {
                char* serialHex = BN_bn2hex(serialBn.get());
                if (serialHex != nullptr)
                {
                    text += "SerialHex: " + std::string(serialHex) + "\n";
                    OPENSSL_free(serialHex);
                }
            }
        }

        text += "NotBefore: " + Asn1TimeToString(X509_get0_notBefore(cert.get())) + "\n";
        text += "NotAfter: " + Asn1TimeToString(X509_get0_notAfter(cert.get())) + "\n";

        {
            const int sigNid = X509_get_signature_nid(cert.get());
            const char* sigName = OBJ_nid2ln(sigNid);
            text += "SignatureAlgorithm: " + std::string(sigName != nullptr ? sigName : "unknown") + "\n";
        }

        {
            EVP_PKEY* pub = X509_get0_pubkey(cert.get());
            if (pub != nullptr)
            {
                const int keyNid = EVP_PKEY_id(pub);
                const char* keyName = OBJ_nid2ln(keyNid);
                text += "PublicKeyAlgorithm: " + std::string(keyName != nullptr ? keyName : "unknown") +
                        " (" + std::to_string(EVP_PKEY_bits(pub)) + " bits)\n";
            }
        }

        {
            GeneralNamesPtr sanNames(static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr)));
            std::string sanText;
            if (sanNames)
            {
                const int count = sk_GENERAL_NAME_num(sanNames.get());
                for (int i = 0; i < count; ++i)
                {
                    GENERAL_NAME* entry = sk_GENERAL_NAME_value(sanNames.get(), i);
                    if (entry != nullptr && entry->type == GEN_DNS)
                    {
                        const unsigned char* dnsData = ASN1_STRING_get0_data(entry->d.dNSName);
                        const int dnsLen = ASN1_STRING_length(entry->d.dNSName);
                        if (!sanText.empty()) sanText += ",";
                        sanText += std::string(reinterpret_cast<const char*>(dnsData), static_cast<std::size_t>(dnsLen));
                    }
                }
            }
            text += "SubjectAltNames: " + sanText + "\n";
        }

        {
            BitStringPtr keyUsage(static_cast<ASN1_BIT_STRING*>(X509_get_ext_d2i(cert.get(), NID_key_usage, nullptr, nullptr)));
            std::string kuText;
            if (keyUsage)
            {
                if (ASN1_BIT_STRING_get_bit(keyUsage.get(), 0)) kuText += "digitalSignature,";
                if (ASN1_BIT_STRING_get_bit(keyUsage.get(), 1)) kuText += "nonRepudiation,";
                if (ASN1_BIT_STRING_get_bit(keyUsage.get(), 2)) kuText += "keyEncipherment,";
                if (ASN1_BIT_STRING_get_bit(keyUsage.get(), 5)) kuText += "keyCertSign,";
                if (ASN1_BIT_STRING_get_bit(keyUsage.get(), 6)) kuText += "cRLSign,";
                if (!kuText.empty()) kuText.pop_back();
            }
            text += "KeyUsage: " + kuText + "\n";
        }

        {
            ExtKeyUsagePtr extKeyUsage(static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(cert.get(), NID_ext_key_usage, nullptr, nullptr)));
            std::string ekuText;
            if (extKeyUsage)
            {
                const int count = sk_ASN1_OBJECT_num(extKeyUsage.get());
                for (int i = 0; i < count; ++i)
                {
                    ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(extKeyUsage.get(), i);
                    char oidText[128];
                    OBJ_obj2txt(oidText, sizeof(oidText), obj, 0);
                    if (!ekuText.empty()) ekuText += ",";
                    ekuText += oidText;
                }
            }
            text += "ExtendedKeyUsage: " + ekuText + "\n";
        }

        {
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int digestLen = 0;
            if (X509_digest(cert.get(), EVP_sha256(), digest, &digestLen) == 1)
            {
                text += "FingerprintSha256Hex: " + BytesToHexString(digest, digestLen) + "\n";
            }
        }

        return WriteTextOut(text, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::ConvertCertificateDerToPem( const unsigned char* derBuffer, const int derBufferSize,
                                                     const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const
{
    try
    {
        if (derBuffer == nullptr || derBufferSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        X509Ptr cert(DerBufferToX509(derBuffer, derBufferSize));
        if (!cert)
        {
            return INVALID_DATA;
        }

        BioPtr bio(BIO_new(BIO_s_mem()));
        if (!bio || PEM_write_bio_X509(bio.get(), cert.get()) != 1)
        {
            return UNEXPECTED_ERROR;
        }
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio.get(), &data);
        if (len < 0 || data == nullptr)
        {
            return UNEXPECTED_ERROR;
        }

        return WriteTextOut(std::string(data, static_cast<std::size_t>(len)), outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::ConvertCertificatePemToDer( const char* pemString, const int pemStringSize,
                                                     const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) const
{
    try
    {
        if (pemString == nullptr || pemStringSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        BioPtr bio(BIO_new_mem_buf(pemString, pemStringSize));
        if (!bio)
        {
            return UNEXPECTED_ERROR;
        }
        X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (!cert)
        {
            return INVALID_DATA;
        }

        std::vector<unsigned char> der;
        if (!X509ToDerBuffer(cert.get(), der))
        {
            return UNEXPECTED_ERROR;
        }

        return WriteDerOut(der, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::ImportPfx( const unsigned char* pfxBuffer, const int pfxBufferSize,
                                    const char* password, const int passwordSize,
                                    const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize,
                                    const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize)
{
    try
    {
        if (pfxBuffer == nullptr || pfxBufferSize <= 0 || certOutputSize == nullptr || keyOutputSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const unsigned char* p = pfxBuffer;
        Pkcs12Ptr p12(d2i_PKCS12(nullptr, &p, pfxBufferSize));
        if (!p12)
        {
            return INVALID_DATA;
        }

        const std::string passwordString(password != nullptr ? password : "", password != nullptr ? passwordSize : 0);

        EVP_PKEY* pkeyRaw = nullptr;
        X509* certRaw = nullptr;
        if (PKCS12_parse(p12.get(), passwordString.c_str(), &pkeyRaw, &certRaw, nullptr) != 1)
        {
            return INVALID_DATA;
        }
        EvpPkeyPtr pkey(pkeyRaw);
        X509Ptr cert(certRaw);

        std::vector<unsigned char> certDer;
        std::string keyPem;
        if (!X509ToDerBuffer(cert.get(), certDer) || !PrivateKeyToPemString(pkey.get(), keyPem))
        {
            return UNEXPECTED_ERROR;
        }

        *certOutputSize = static_cast<int>(certDer.size());
        *keyOutputSize = static_cast<int>(keyPem.size());
        if (certOutputBuffer == nullptr || certOutputCapacity < *certOutputSize ||
            keyOutputBuffer == nullptr || keyOutputCapacity < *keyOutputSize)
        {
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(certOutputBuffer, certDer.data(), certDer.size());
        std::memcpy(keyOutputBuffer, keyPem.data(), keyPem.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::ExportPfx( const unsigned char* certDerBuffer, const int certDerBufferSize,
                                    const char* privateKeyPem, const int privateKeyPemSize,
                                    const char* password, const int passwordSize,
                                    const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (certDerBuffer == nullptr || certDerBufferSize <= 0 ||
            privateKeyPem == nullptr || privateKeyPemSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        X509Ptr cert(DerBufferToX509(certDerBuffer, certDerBufferSize));
        if (!cert)
        {
            return INVALID_DATA;
        }
        EvpPkeyPtr pkey(PemBufferToPrivateKey(privateKeyPem, privateKeyPemSize));
        if (!pkey)
        {
            return INVALID_DATA;
        }

        const std::string passwordString(password != nullptr ? password : "", password != nullptr ? passwordSize : 0);

        Pkcs12Ptr p12(PKCS12_create(passwordString.c_str(), "CryptoAPI", pkey.get(), cert.get(), nullptr, 0, 0, 0, 0, 0));
        if (!p12)
        {
            return UNEXPECTED_ERROR;
        }

        unsigned char* derPtr = nullptr;
        const int derLen = i2d_PKCS12(p12.get(), &derPtr);
        if (derLen <= 0 || derPtr == nullptr)
        {
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> der(derPtr, derPtr + derLen);
        OPENSSL_free(derPtr);

        return WriteDerOut(der, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::CreateSelfSignedCertificate( const char* subjectCommonName, const int subjectCommonNameSize,
                                                      const char* sanDnsNamesCsv, const int sanDnsNamesCsvSize,
                                                      const CertificateKeyAlgorithm keyAlgorithm, const int validityDays,
                                                      const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                                      const CertificateDigestAlgorithm digestAlgorithm,
                                                      const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize,
                                                      const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize)
{
    try
    {
        // validityDays==0 is allowed deliberately: notAfter==notBefore, i.e. "expires
        // immediately" -- used by RunCertificateChainExpiredTest (CryptoApiTester.cpp) to produce
        // an already-expired certificate without waiting out a real 1-day-minimum window.
        if (subjectCommonName == nullptr || subjectCommonNameSize <= 0 || validityDays < 0 ||
            certOutputSize == nullptr || keyOutputSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const std::string cn(subjectCommonName, subjectCommonNameSize);
        const std::string sanCsv(sanDnsNamesCsv != nullptr ? sanDnsNamesCsv : "", sanDnsNamesCsv != nullptr ? sanDnsNamesCsvSize : 0);

        EvpPkeyPtr pkey(GenerateKeyPairForAlgorithm(keyAlgorithm));
        if (!pkey)
        {
            return UNEXPECTED_ERROR;
        }

        X509Ptr cert(X509_new());
        if (!cert)
        {
            return UNEXPECTED_ERROR;
        }
        X509_set_version(cert.get(), 2);

        {
            BnPtr serialBn(BN_new());
            Asn1IntegerPtr serial(ASN1_INTEGER_new());
            if (!serialBn || !serial || BN_rand(serialBn.get(), 128, 0, 0) != 1 ||
                BN_to_ASN1_INTEGER(serialBn.get(), serial.get()) == nullptr ||
                X509_set_serialNumber(cert.get(), serial.get()) != 1)
            {
                return UNEXPECTED_ERROR;
            }
        }

        {
            X509_NAME* name = X509_NAME_new();
            if (name == nullptr)
            {
                return UNEXPECTED_ERROR;
            }
            const bool nameOk = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0) == 1 &&
                                X509_set_subject_name(cert.get(), name) == 1 && X509_set_issuer_name(cert.get(), name) == 1;
            X509_NAME_free(name);
            if (!nameOk)
            {
                return UNEXPECTED_ERROR;
            }
        }
        X509_set_pubkey(cert.get(), pkey.get());

        if (!SetCertificateValidityPeriod(cert.get(), validityDays))
        {
            return UNEXPECTED_ERROR;
        }
        if (!AddSanExtensionToCertificate(cert.get(), sanCsv))
        {
            return UNEXPECTED_ERROR;
        }
        if (!AddKeyUsageExtensions(cert.get(), keyUsageFlags, extendedKeyUsageFlags))
        {
            return UNEXPECTED_ERROR;
        }

        if (X509_sign(cert.get(), pkey.get(), CertificateDigestToEvpMd(digestAlgorithm)) <= 0)
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> certDer;
        std::string keyPem;
        if (!X509ToDerBuffer(cert.get(), certDer) || !PrivateKeyToPemString(pkey.get(), keyPem))
        {
            return UNEXPECTED_ERROR;
        }

        *certOutputSize = static_cast<int>(certDer.size());
        *keyOutputSize = static_cast<int>(keyPem.size());
        if (certOutputBuffer == nullptr || certOutputCapacity < *certOutputSize ||
            keyOutputBuffer == nullptr || keyOutputCapacity < *keyOutputSize)
        {
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(certOutputBuffer, certDer.data(), certDer.size());
        std::memcpy(keyOutputBuffer, keyPem.data(), keyPem.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::CreateCertificateRequest( const char* subjectCommonName, const int subjectCommonNameSize,
                                                   const char* sanDnsNamesCsv, const int sanDnsNamesCsvSize,
                                                   const CertificateKeyAlgorithm keyAlgorithm, const CertificateDigestAlgorithm digestAlgorithm,
                                                   const int csrOutputCapacity, unsigned char* csrOutputBuffer, int* csrOutputSize,
                                                   const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize)
{
    try
    {
        if (subjectCommonName == nullptr || subjectCommonNameSize <= 0 ||
            csrOutputSize == nullptr || keyOutputSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const std::string cn(subjectCommonName, subjectCommonNameSize);
        const std::string sanCsv(sanDnsNamesCsv != nullptr ? sanDnsNamesCsv : "", sanDnsNamesCsv != nullptr ? sanDnsNamesCsvSize : 0);

        EvpPkeyPtr pkey(GenerateKeyPairForAlgorithm(keyAlgorithm));
        if (!pkey)
        {
            return UNEXPECTED_ERROR;
        }

        X509ReqPtr req(X509_REQ_new());
        if (!req)
        {
            return UNEXPECTED_ERROR;
        }
        X509_REQ_set_version(req.get(), 0);

        {
            X509_NAME* name = X509_NAME_new();
            if (name == nullptr)
            {
                return UNEXPECTED_ERROR;
            }
            const bool nameOk = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0) == 1 &&
                                X509_REQ_set_subject_name(req.get(), name) == 1;
            X509_NAME_free(name);
            if (!nameOk)
            {
                return UNEXPECTED_ERROR;
            }
        }
        if (X509_REQ_set_pubkey(req.get(), pkey.get()) != 1)
        {
            return UNEXPECTED_ERROR;
        }
        if (!AddSanExtensionToRequest(req.get(), sanCsv))
        {
            return UNEXPECTED_ERROR;
        }
        if (X509_REQ_sign(req.get(), pkey.get(), CertificateDigestToEvpMd(digestAlgorithm)) <= 0)
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> csrDer;
        std::string keyPem;
        if (!X509ReqToDerBuffer(req.get(), csrDer) || !PrivateKeyToPemString(pkey.get(), keyPem))
        {
            return UNEXPECTED_ERROR;
        }

        *csrOutputSize = static_cast<int>(csrDer.size());
        *keyOutputSize = static_cast<int>(keyPem.size());
        if (csrOutputBuffer == nullptr || csrOutputCapacity < *csrOutputSize ||
            keyOutputBuffer == nullptr || keyOutputCapacity < *keyOutputSize)
        {
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(csrOutputBuffer, csrDer.data(), csrDer.size());
        std::memcpy(keyOutputBuffer, keyPem.data(), keyPem.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::IssueCertificateFromRequest( const unsigned char* csrDerBuffer, const int csrDerBufferSize,
                                                      const unsigned char* caCertDerBuffer, const int caCertDerBufferSize,
                                                      const char* caPrivateKeyPem, const int caPrivateKeyPemSize,
                                                      const int validityDays, const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                                      const CertificateDigestAlgorithm digestAlgorithm,
                                                      const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize)
{
    try
    {
        // validityDays==0 is allowed deliberately -- see CreateSelfSignedCertificate's identical
        // comment.
        if (csrDerBuffer == nullptr || csrDerBufferSize <= 0 ||
            caCertDerBuffer == nullptr || caCertDerBufferSize <= 0 ||
            caPrivateKeyPem == nullptr || caPrivateKeyPemSize <= 0 ||
            validityDays < 0 || certOutputSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        X509ReqPtr req(DerBufferToX509Req(csrDerBuffer, csrDerBufferSize));
        if (!req)
        {
            return INVALID_DATA;
        }
        EvpPkeyPtr reqPubKey(X509_REQ_get_pubkey(req.get()));
        if (!reqPubKey || X509_REQ_verify(req.get(), reqPubKey.get()) != 1)
        {
            return INVALID_DATA;
        }

        X509Ptr caCert(DerBufferToX509(caCertDerBuffer, caCertDerBufferSize));
        if (!caCert)
        {
            return INVALID_DATA;
        }
        EvpPkeyPtr caKey(PemBufferToPrivateKey(caPrivateKeyPem, caPrivateKeyPemSize));
        if (!caKey)
        {
            return INVALID_DATA;
        }
        if (X509_check_private_key(caCert.get(), caKey.get()) != 1)
        {
            return INVALID_ARGUMENT;
        }

        X509Ptr cert(X509_new());
        if (!cert)
        {
            return UNEXPECTED_ERROR;
        }
        X509_set_version(cert.get(), 2);

        {
            BnPtr serialBn(BN_new());
            Asn1IntegerPtr serial(ASN1_INTEGER_new());
            if (!serialBn || !serial || BN_rand(serialBn.get(), 128, 0, 0) != 1 ||
                BN_to_ASN1_INTEGER(serialBn.get(), serial.get()) == nullptr ||
                X509_set_serialNumber(cert.get(), serial.get()) != 1)
            {
                return UNEXPECTED_ERROR;
            }
        }

        X509_set_issuer_name(cert.get(), X509_get_subject_name(caCert.get()));
        X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(req.get()));
        X509_set_pubkey(cert.get(), reqPubKey.get());

        if (!SetCertificateValidityPeriod(cert.get(), validityDays))
        {
            return UNEXPECTED_ERROR;
        }
        if (!CopySanExtensionFromRequest(req.get(), cert.get()))
        {
            return UNEXPECTED_ERROR;
        }
        if (!AddKeyUsageExtensions(cert.get(), keyUsageFlags, extendedKeyUsageFlags))
        {
            return UNEXPECTED_ERROR;
        }

        if (X509_sign(cert.get(), caKey.get(), CertificateDigestToEvpMd(digestAlgorithm)) <= 0)
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> certDer;
        if (!X509ToDerBuffer(cert.get(), certDer))
        {
            return UNEXPECTED_ERROR;
        }

        return WriteDerOut(certDer, certOutputCapacity, certOutputBuffer, certOutputSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::AddIntermediateCertificateForChainValidation(const unsigned char* certDerBuffer, const int certDerBufferSize)
{
    try
    {
        if (certDerBuffer == nullptr || certDerBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        impl_->intermediateCerts.push_back(std::vector<unsigned char>(certDerBuffer, certDerBuffer + certDerBufferSize));
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::ClearIntermediateCertificatesForChainValidation(void)
{
    try
    {
        impl_->intermediateCerts.clear();
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::ValidateChain( const unsigned char* leafCertDerBuffer, const int leafCertDerBufferSize,
                                        const RevocationMode revocationMode, const RevocationNetworkMode revocationNetworkMode,
                                        int* trustResult, int* revocationStatus)
{
    try
    {
        if (leafCertDerBuffer == nullptr || leafCertDerBufferSize <= 0 || trustResult == nullptr || revocationStatus == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        PCCERT_CONTEXT leafCtx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, leafCertDerBuffer, static_cast<DWORD>(leafCertDerBufferSize));
        if (leafCtx == nullptr)
        {
            return INVALID_DATA;
        }

        HCERTSTORE additionalStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
        HCERTSTORE exclusiveRootStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
        if (additionalStore == nullptr || exclusiveRootStore == nullptr)
        {
            CertFreeCertificateContext(leafCtx);
            if (additionalStore != nullptr) CertCloseStore(additionalStore, 0);
            if (exclusiveRootStore != nullptr) CertCloseStore(exclusiveRootStore, 0);
            return UNEXPECTED_ERROR;
        }

        // Self-signed candidates (Subject == Issuer) among the accumulated intermediates become
        // this validation call's trust anchors -- Plan.md 25.6's "ApplicationTrust" mode,
        // deliberately chosen over SystemTrust so this method (and the automated test suite) never
        // reads from or mutates the real Windows Root store.
        for (std::size_t i = 0; i < impl_->intermediateCerts.size(); ++i)
        {
            const std::vector<unsigned char>& derCert = impl_->intermediateCerts[i];
            CertAddEncodedCertificateToStore( additionalStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              derCert.data(), static_cast<DWORD>(derCert.size()), CERT_STORE_ADD_ALWAYS, nullptr);

            PCCERT_CONTEXT candidateCtx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derCert.data(), static_cast<DWORD>(derCert.size()));
            if (candidateCtx != nullptr)
            {
                if (CertCompareCertificateName(X509_ASN_ENCODING, &candidateCtx->pCertInfo->Subject, &candidateCtx->pCertInfo->Issuer))
                {
                    CertAddEncodedCertificateToStore( exclusiveRootStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                      derCert.data(), static_cast<DWORD>(derCert.size()), CERT_STORE_ADD_ALWAYS, nullptr);
                }
                CertFreeCertificateContext(candidateCtx);
            }
        }

        CERT_CHAIN_ENGINE_CONFIG engineConfig;
        ZeroMemory(&engineConfig, sizeof(engineConfig));
        engineConfig.cbSize = sizeof(engineConfig);
        engineConfig.hExclusiveRoot = exclusiveRootStore;

        HCERTCHAINENGINE chainEngine = nullptr;
        if (!CertCreateCertificateChainEngine(&engineConfig, &chainEngine))
        {
            CertFreeCertificateContext(leafCtx);
            CertCloseStore(additionalStore, 0);
            CertCloseStore(exclusiveRootStore, 0);
            return UNEXPECTED_ERROR;
        }

        CERT_CHAIN_PARA chainPara;
        ZeroMemory(&chainPara, sizeof(chainPara));
        chainPara.cbSize = sizeof(chainPara);

        DWORD chainFlags = 0;
        if (revocationMode != REVOCATION_MODE_DISABLED)
        {
            chainFlags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
        }
        if (revocationNetworkMode != REVOCATION_NETWORK_ONLINE)
        {
            chainFlags |= CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
        }

        PCCERT_CHAIN_CONTEXT chainContext = nullptr;
        const BOOL gotChain = CertGetCertificateChain(chainEngine, leafCtx, nullptr, additionalStore, &chainPara, chainFlags, nullptr, &chainContext);

        int localTrust = CERTIFICATE_TRUST_INDETERMINATE;
        int localRevocation = REVOCATION_STATUS_NOT_CHECKED;

        if (gotChain && chainContext != nullptr)
        {
            const DWORD errorStatus = chainContext->TrustStatus.dwErrorStatus;

            if (revocationMode == REVOCATION_MODE_DISABLED)
            {
                localRevocation = REVOCATION_STATUS_NOT_CHECKED;
            }
            else if ((errorStatus & CERT_TRUST_IS_REVOKED) != 0)
            {
                localRevocation = REVOCATION_STATUS_REVOKED;
            }
            else if ((errorStatus & (CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION)) != 0)
            {
                localRevocation = REVOCATION_STATUS_UNKNOWN;
            }
            else
            {
                localRevocation = REVOCATION_STATUS_GOOD;
            }

            CERT_CHAIN_POLICY_PARA policyPara;
            ZeroMemory(&policyPara, sizeof(policyPara));
            policyPara.cbSize = sizeof(policyPara);

            CERT_CHAIN_POLICY_STATUS policyStatus;
            ZeroMemory(&policyStatus, sizeof(policyStatus));
            policyStatus.cbSize = sizeof(policyStatus);

            const BOOL policyOk = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, chainContext, &policyPara, &policyStatus);

            if (revocationMode == REVOCATION_MODE_REQUIRED && localRevocation == REVOCATION_STATUS_UNKNOWN)
            {
                localTrust = CERTIFICATE_TRUST_INDETERMINATE;
            }
            else if (localRevocation == REVOCATION_STATUS_REVOKED)
            {
                localTrust = CERTIFICATE_TRUST_UNTRUSTED;
            }
            else if (policyOk && policyStatus.dwError == 0)
            {
                localTrust = CERTIFICATE_TRUST_TRUSTED;
            }
            else
            {
                localTrust = CERTIFICATE_TRUST_UNTRUSTED;
            }

            CertFreeCertificateChain(chainContext);
        }
        else
        {
            localTrust = CERTIFICATE_TRUST_INDETERMINATE;
            localRevocation = REVOCATION_STATUS_UNKNOWN;
        }

        CertFreeCertificateContext(leafCtx);
        CertFreeCertificateChainEngine(chainEngine);
        CertCloseStore(additionalStore, 0);
        CertCloseStore(exclusiveRootStore, 0);

        *trustResult = localTrust;
        *revocationStatus = localRevocation;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::CheckCertificateAgainstCrl( const unsigned char* certDerBuffer, const int certDerBufferSize,
                                                      const unsigned char* crlDerBuffer, const int crlDerBufferSize,
                                                      const unsigned char* crlIssuerCertDerBuffer, const int crlIssuerCertDerBufferSize,
                                                      int* revocationStatus)
{
    try
    {
        if (certDerBuffer == nullptr || certDerBufferSize <= 0 ||
            crlDerBuffer == nullptr || crlDerBufferSize <= 0 || revocationStatus == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        X509Ptr cert(DerBufferToX509(certDerBuffer, certDerBufferSize));
        if (!cert)
        {
            return INVALID_DATA;
        }

        const unsigned char* crlP = crlDerBuffer;
        X509CrlPtr crl(d2i_X509_CRL(nullptr, &crlP, crlDerBufferSize));
        if (!crl)
        {
            return INVALID_DATA;
        }

        if (crlIssuerCertDerBuffer != nullptr && crlIssuerCertDerBufferSize > 0)
        {
            X509Ptr issuerCert(DerBufferToX509(crlIssuerCertDerBuffer, crlIssuerCertDerBufferSize));
            if (!issuerCert)
            {
                return INVALID_DATA;
            }

            EvpPkeyPtr issuerPubKey(X509_get_pubkey(issuerCert.get()));
            if (!issuerPubKey || X509_CRL_verify(crl.get(), issuerPubKey.get()) != 1)
            {
                *revocationStatus = REVOCATION_STATUS_UNKNOWN;
                return NO_ERROR;
            }
        }

        // A CRL past its own nextUpdate is stale -- "not listed as revoked" from a stale CRL isn't
        // trustworthy evidence of the certificate's current status. ASN1_TIME_cmp_time_t (not
        // X509_cmp_current_time, deprecated since OpenSSL 4.0) returns <0 when nextUpdate is
        // earlier than the given time_t.
        const ASN1_TIME* nextUpdate = X509_CRL_get0_nextUpdate(crl.get());
        if (nextUpdate != nullptr && ASN1_TIME_cmp_time_t(nextUpdate, std::time(nullptr)) < 0)
        {
            *revocationStatus = REVOCATION_STATUS_UNKNOWN;
            return NO_ERROR;
        }

        X509_REVOKED* revokedEntry = nullptr;
        const int found = X509_CRL_get0_by_serial(crl.get(), &revokedEntry, X509_get_serialNumber(cert.get()));

        *revocationStatus = (found == 1) ? REVOCATION_STATUS_REVOKED : REVOCATION_STATUS_GOOD;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::OpenStore(const CertificateStoreLocation location)
{
    try
    {
        if (impl_->storeOpen)
        {
            return INVALID_ARGUMENT;
        }

        HCERTSTORE store = nullptr;
        switch (location)
        {
        case CERTIFICATE_STORE_MEMORY:
            store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
            break;
        case CERTIFICATE_STORE_CURRENT_USER:
            store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
            break;
        case CERTIFICATE_STORE_LOCAL_MACHINE:
            store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
            break;
        default:
            return INVALID_ARGUMENT;
        }
        if (store == nullptr)
        {
            return UNEXPECTED_ERROR;
        }

        impl_->openStore = store;
        impl_->storeOpen = true;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::CloseStore(void)
{
    try
    {
        if (!impl_->storeOpen)
        {
            return INVALID_ARGUMENT;
        }
        CertCloseStore(impl_->openStore, 0);
        impl_->openStore = nullptr;
        impl_->storeOpen = false;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::AddCertificateToStore(const unsigned char* certDerBuffer, const int certDerBufferSize)
{
    try
    {
        if (!impl_->storeOpen || certDerBuffer == nullptr || certDerBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (!CertAddEncodedCertificateToStore( impl_->openStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              certDerBuffer, static_cast<DWORD>(certDerBufferSize), CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
        {
            return UNEXPECTED_ERROR;
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::RemoveCertificateFromStore(const unsigned char* certDerBuffer, const int certDerBufferSize)
{
    try
    {
        if (!impl_->storeOpen || certDerBuffer == nullptr || certDerBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }

        PCCERT_CONTEXT matchCtx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certDerBuffer, static_cast<DWORD>(certDerBufferSize));
        if (matchCtx == nullptr)
        {
            return INVALID_DATA;
        }

        PCCERT_CONTEXT foundCtx = CertFindCertificateInStore(impl_->openStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_EXISTING, matchCtx, nullptr);
        CertFreeCertificateContext(matchCtx);
        if (foundCtx == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        // CertDeleteCertificateFromStore always frees foundCtx internally, regardless of return value.
        if (!CertDeleteCertificateFromStore(foundCtx))
        {
            return UNEXPECTED_ERROR;
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::FindCertificateInStoreBySubject( const char* subjectSubstring, const int subjectSubstringSize,
                                                          const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_->storeOpen || subjectSubstring == nullptr || subjectSubstringSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const std::wstring wideSubject = Utf8ToWide(subjectSubstring, subjectSubstringSize);
        PCCERT_CONTEXT foundCtx = CertFindCertificateInStore( impl_->openStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                                              CERT_FIND_SUBJECT_STR, wideSubject.c_str(), nullptr);
        if (foundCtx == nullptr)
        {
            *outputBufferSize = 0;
            return INVALID_ARGUMENT;
        }

        const int result = WriteBytesOut(foundCtx->pbCertEncoded, foundCtx->cbCertEncoded, outputBufferCapacity, outputBuffer, outputBufferSize);
        CertFreeCertificateContext(foundCtx);
        return result;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCertificateManager::ImportPfxToStore( const unsigned char* pfxBuffer, const int pfxBufferSize,
                                          const char* password, const int passwordSize)
{
    try
    {
        if (!impl_->storeOpen || pfxBuffer == nullptr || pfxBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }

        CRYPT_DATA_BLOB blob;
        blob.pbData = const_cast<BYTE*>(pfxBuffer);
        blob.cbData = static_cast<DWORD>(pfxBufferSize);

        const std::wstring widePassword = Utf8ToWide(password, passwordSize);
        HCERTSTORE tempStore = PFXImportCertStore(&blob, widePassword.c_str(), CRYPT_EXPORTABLE);
        if (tempStore == nullptr)
        {
            return INVALID_DATA;
        }

        PCCERT_CONTEXT enumCtx = nullptr;
        while ((enumCtx = CertEnumCertificatesInStore(tempStore, enumCtx)) != nullptr)
        {
            CertAddCertificateContextToStore(impl_->openStore, enumCtx, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
        }
        CertCloseStore(tempStore, 0);
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

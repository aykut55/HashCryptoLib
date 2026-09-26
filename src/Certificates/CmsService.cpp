#include "CmsService.h"
#include "Definitions/Definitions.h"

#include "openssl/bio.h"
#include "openssl/cms.h"
#include "openssl/err.h"
#include "openssl/ess.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace CryptoApiNS
{

namespace
{

struct X509Deleter        { void operator()(X509* p)             const { if (p) X509_free(p); } };
struct EvpPkeyDeleter      { void operator()(EVP_PKEY* p)         const { if (p) EVP_PKEY_free(p); } };
struct BioDeleter          { void operator()(BIO* p)              const { if (p) BIO_free(p); } };
struct CmsContentInfoDeleter { void operator()(CMS_ContentInfo* p) const { if (p) CMS_ContentInfo_free(p); } };
struct X509StoreDeleter    { void operator()(X509_STORE* p)       const { if (p) X509_STORE_free(p); } };
struct X509StackDeleter    { void operator()(STACK_OF(X509)* p)   const { if (p) sk_X509_pop_free(p, X509_free); } };
struct EssSigningCertV2Deleter { void operator()(ESS_SIGNING_CERT_V2* p) const { if (p) ESS_SIGNING_CERT_V2_free(p); } };

typedef std::unique_ptr<X509, X509Deleter> X509Ptr;
typedef std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> EvpPkeyPtr;
typedef std::unique_ptr<BIO, BioDeleter> BioPtr;
typedef std::unique_ptr<CMS_ContentInfo, CmsContentInfoDeleter> CmsContentInfoPtr;
typedef std::unique_ptr<X509_STORE, X509StoreDeleter> X509StorePtr;
typedef std::unique_ptr<STACK_OF(X509), X509StackDeleter> X509StackPtr;
typedef std::unique_ptr<ESS_SIGNING_CERT_V2, EssSigningCertV2Deleter> EssSigningCertV2Ptr;

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

X509* DerBufferToX509(const unsigned char* buffer, const int bufferSize)
{
    const unsigned char* p = buffer;
    return d2i_X509(nullptr, &p, bufferSize);
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

const EVP_MD* CmsDigestToEvpMd(const CmsDigestAlgorithm digestAlgorithm)
{
    switch (digestAlgorithm)
    {
    case CMS_DIGEST_SHA384: return EVP_sha384();
    case CMS_DIGEST_SHA512: return EVP_sha512();
    default:                return EVP_sha256();
    }
}
// -----------------------------------------------------------------------------

// Reads the signing-certificate-v2 attribute (if any) off cms's single SignerInfo and confirms it
// names actualSignerCert -- ESS_SIGNING_CERT_V2's own DER encoding is stored verbatim as the
// attribute's V_ASN1_SEQUENCE value (OpenSSL's own convention for embedding a pre-encoded ASN.1
// structure as a CMS signed attribute; see X509_ATTRIBUTE_get0_type's own doc). Returns true when
// no such attribute is present at all (a CMS blob from something other than SignDetached above,
// which always adds one) -- this check only ever turns a would-be VALID into
// CMS_VERIFICATION_SIGNING_CERT_MISMATCH, never the reverse.
bool CmsSigningCertMatchesSigner(CMS_ContentInfo* cms, X509* actualSignerCert)
{
    STACK_OF(CMS_SignerInfo)* signerInfos = CMS_get0_SignerInfos(cms);
    if (signerInfos == nullptr || sk_CMS_SignerInfo_num(signerInfos) < 1)
    {
        return true;
    }
    CMS_SignerInfo* signerInfo = sk_CMS_SignerInfo_value(signerInfos, 0);

    const int attrLoc = CMS_signed_get_attr_by_NID(signerInfo, NID_id_smime_aa_signingCertificateV2, -1);
    if (attrLoc < 0)
    {
        return true;
    }
    X509_ATTRIBUTE* attr = CMS_signed_get_attr(signerInfo, attrLoc);
    if (attr == nullptr || X509_ATTRIBUTE_count(attr) < 1)
    {
        return true;
    }
    const ASN1_TYPE* attrValue = X509_ATTRIBUTE_get0_type(attr, 0);
    if (attrValue == nullptr || attrValue->type != V_ASN1_SEQUENCE || attrValue->value.sequence == nullptr)
    {
        return true;
    }

    const unsigned char* p = ASN1_STRING_get0_data(attrValue->value.sequence);
    const int len = ASN1_STRING_length(attrValue->value.sequence);
    EssSigningCertV2Ptr signingCertV2(d2i_ESS_SIGNING_CERT_V2(nullptr, &p, len));
    if (!signingCertV2)
    {
        return true;
    }

    // A plain sk_X509_free (NOT the X509StackPtr/pop_free RAII wrapper used elsewhere in this file)
    // -- actualSignerCert is borrowed from the caller, this stack must never free its elements.
    STACK_OF(X509)* singleCertStack = sk_X509_new_null();
    if (singleCertStack == nullptr || sk_X509_push(singleCertStack, actualSignerCert) <= 0)
    {
        sk_X509_free(singleCertStack);
        return true;
    }

    const int checkRc = OSSL_ESS_check_signing_certs(nullptr, signingCertV2.get(), singleCertStack, 1);
    sk_X509_free(singleCertStack);
    return checkRc == 1;
}
// -----------------------------------------------------------------------------

} // namespace

CCmsService::~CCmsService()
{
}
// -----------------------------------------------------------------------------

CCmsService::CCmsService()
{
}
// -----------------------------------------------------------------------------

int CCmsService::SignDetached( const unsigned char* dataBuffer, const int dataBufferSize,
                               const unsigned char* signerCertDerBuffer, const int signerCertDerBufferSize,
                               const char* signerPrivateKeyPem, const int signerPrivateKeyPemSize,
                               const CmsDigestAlgorithm digestAlgorithm,
                               const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (dataBuffer == nullptr || dataBufferSize <= 0 ||
            signerCertDerBuffer == nullptr || signerCertDerBufferSize <= 0 ||
            signerPrivateKeyPem == nullptr || signerPrivateKeyPemSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        X509Ptr signerCert(DerBufferToX509(signerCertDerBuffer, signerCertDerBufferSize));
        if (!signerCert)
        {
            return INVALID_DATA;
        }
        EvpPkeyPtr signerKey(PemBufferToPrivateKey(signerPrivateKeyPem, signerPrivateKeyPemSize));
        if (!signerKey)
        {
            return INVALID_DATA;
        }

        BioPtr dataBio(BIO_new_mem_buf(dataBuffer, dataBufferSize));
        if (!dataBio)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int signFlags = CMS_PARTIAL | CMS_DETACHED | CMS_BINARY;
        CmsContentInfoPtr cms(CMS_sign(nullptr, nullptr, nullptr, dataBio.get(), signFlags));
        if (!cms)
        {
            return UNEXPECTED_ERROR;
        }

        CMS_SignerInfo* signerInfo = CMS_add1_signer( cms.get(), signerCert.get(), signerKey.get(), CmsDigestToEvpMd(digestAlgorithm),
                                                      CMS_DETACHED | CMS_BINARY | CMS_NOSMIMECAP);
        if (signerInfo == nullptr)
        {
            return UNEXPECTED_ERROR;
        }

        // RFC 5035 signing-certificate-v2 signed attribute: binds this signature to signerCert
        // specifically (its SHA-256 hash + issuer/serial), defending against a certificate being
        // substituted for a different one the actual signature would still verify against. Always
        // SHA-256 per RFC 5035's own recommendation, independent of digestAlgorithm (the message
        // digest algorithm above). Must be added to signerInfo BEFORE CMS_final, since signed
        // attributes are themselves covered by the signature CMS_final computes.
        {
            EssSigningCertV2Ptr signingCertV2(OSSL_ESS_signing_cert_v2_new_init(EVP_sha256(), signerCert.get(), nullptr, 1));
            if (!signingCertV2)
            {
                return UNEXPECTED_ERROR;
            }

            unsigned char* essDerPtr = nullptr;
            const int essDerLen = i2d_ESS_SIGNING_CERT_V2(signingCertV2.get(), &essDerPtr);
            if (essDerLen <= 0 || essDerPtr == nullptr)
            {
                return UNEXPECTED_ERROR;
            }

            const int addRc = CMS_signed_add1_attr_by_NID( signerInfo, NID_id_smime_aa_signingCertificateV2,
                                                           V_ASN1_SEQUENCE, essDerPtr, essDerLen);
            OPENSSL_free(essDerPtr);
            if (addRc != 1)
            {
                return UNEXPECTED_ERROR;
            }
        }

        if (CMS_final(cms.get(), dataBio.get(), nullptr, CMS_DETACHED | CMS_BINARY) != 1)
        {
            return UNEXPECTED_ERROR;
        }

        unsigned char* derPtr = nullptr;
        const int derLen = i2d_CMS_ContentInfo(cms.get(), &derPtr);
        if (derLen <= 0 || derPtr == nullptr)
        {
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> der(derPtr, derPtr + derLen);
        OPENSSL_free(derPtr);

        return WriteBytesOut(der.data(), der.size(), outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCmsService::VerifyDetached( const unsigned char* dataBuffer, const int dataBufferSize,
                                 const unsigned char* cmsDerBuffer, const int cmsDerBufferSize,
                                 const unsigned char* trustedRootCertDerBuffer, const int trustedRootCertDerBufferSize,
                                 int* verificationResult)
{
    try
    {
        if (dataBuffer == nullptr || dataBufferSize <= 0 ||
            cmsDerBuffer == nullptr || cmsDerBufferSize <= 0 || verificationResult == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const unsigned char* p = cmsDerBuffer;
        CmsContentInfoPtr cms(d2i_CMS_ContentInfo(nullptr, &p, cmsDerBufferSize));
        if (!cms)
        {
            *verificationResult = CMS_VERIFICATION_TECHNICAL_ERROR;
            return NO_ERROR;
        }

        // Pass 1: cryptographic-only check, never checks certificate trust -- distinguishes
        // "tampered data / bad signature" from "untrusted signer" deterministically (see this
        // method's own header comment).
        BioPtr dataBio1(BIO_new_mem_buf(dataBuffer, dataBufferSize));
        if (!dataBio1)
        {
            *verificationResult = CMS_VERIFICATION_TECHNICAL_ERROR;
            return NO_ERROR;
        }
        const int cryptoOk = CMS_verify(cms.get(), nullptr, nullptr, dataBio1.get(), nullptr, CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY);
        if (cryptoOk != 1)
        {
            *verificationResult = CMS_VERIFICATION_TAMPERED_DATA;
            return NO_ERROR;
        }

        // RFC 5035 check: confirms a signing-certificate-v2 attribute, if present, actually names
        // the certificate CMS_verify above just used -- gated on this before either outcome below
        // could report VALID, since a mismatch here means the signature is cryptographically sound
        // but was not made the way it claims to have been (a certificate-substitution scenario).
        {
            X509StackPtr signerCerts(CMS_get1_certs(cms.get()));
            if (signerCerts && sk_X509_num(signerCerts.get()) >= 1)
            {
                X509* actualSignerCert = sk_X509_value(signerCerts.get(), 0);
                if (!CmsSigningCertMatchesSigner(cms.get(), actualSignerCert))
                {
                    *verificationResult = CMS_VERIFICATION_SIGNING_CERT_MISMATCH;
                    return NO_ERROR;
                }
            }
        }

        if (trustedRootCertDerBuffer == nullptr || trustedRootCertDerBufferSize <= 0)
        {
            *verificationResult = CMS_VERIFICATION_VALID;
            return NO_ERROR;
        }

        X509Ptr trustedRoot(DerBufferToX509(trustedRootCertDerBuffer, trustedRootCertDerBufferSize));
        if (!trustedRoot)
        {
            return INVALID_ARGUMENT;
        }
        X509StorePtr store(X509_STORE_new());
        if (!store || X509_STORE_add_cert(store.get(), trustedRoot.get()) != 1)
        {
            return UNEXPECTED_ERROR;
        }

        BioPtr dataBio2(BIO_new_mem_buf(dataBuffer, dataBufferSize));
        if (!dataBio2)
        {
            return UNEXPECTED_ERROR;
        }
        const int trustOk = CMS_verify(cms.get(), nullptr, store.get(), dataBio2.get(), nullptr, CMS_BINARY);
        *verificationResult = (trustOk == 1) ? CMS_VERIFICATION_VALID : CMS_VERIFICATION_UNTRUSTED_SIGNER;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCmsService::ExtractSignerCertificate( const unsigned char* cmsDerBuffer, const int cmsDerBufferSize,
                                          const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) const
{
    try
    {
        if (cmsDerBuffer == nullptr || cmsDerBufferSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const unsigned char* p = cmsDerBuffer;
        CmsContentInfoPtr cms(d2i_CMS_ContentInfo(nullptr, &p, cmsDerBufferSize));
        if (!cms)
        {
            return INVALID_DATA;
        }

        X509StackPtr signers(CMS_get1_certs(cms.get()));
        if (!signers || sk_X509_num(signers.get()) < 1)
        {
            return INVALID_DATA;
        }

        X509* signerCert = sk_X509_value(signers.get(), 0);
        unsigned char* derPtr = nullptr;
        const int derLen = i2d_X509(signerCert, &derPtr);
        if (derLen <= 0 || derPtr == nullptr)
        {
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> der(derPtr, derPtr + derLen);
        OPENSSL_free(derPtr);

        return WriteBytesOut(der.data(), der.size(), outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

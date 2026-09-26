#include "CmsService.h"
#include "Definitions/Definitions.h"

#include "openssl/bio.h"
#include "openssl/cms.h"
#include "openssl/err.h"
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

typedef std::unique_ptr<X509, X509Deleter> X509Ptr;
typedef std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> EvpPkeyPtr;
typedef std::unique_ptr<BIO, BioDeleter> BioPtr;
typedef std::unique_ptr<CMS_ContentInfo, CmsContentInfoDeleter> CmsContentInfoPtr;
typedef std::unique_ptr<X509_STORE, X509StoreDeleter> X509StorePtr;
typedef std::unique_ptr<STACK_OF(X509), X509StackDeleter> X509StackPtr;

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

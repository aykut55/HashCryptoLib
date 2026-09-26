#ifndef CRYPTOAPI_ICMS_SERVICE_H
#define CRYPTOAPI_ICMS_SERVICE_H

#include "Definitions/Definitions.h"

namespace CryptoApiNS
{

// Message digest SignDetached signs with -- a deliberately independent, like-named enum from
// ICertificateManager.h's CertificateDigestAlgorithm (see that header's own comment for why: this
// keeps the three new interface headers -- ICertificateManager/ICmsService/ITimestampService --
// from ever needing to include one another).
enum CmsDigestAlgorithm
{
    CMS_DIGEST_SHA256 = 0,
    CMS_DIGEST_SHA384 = 1,
    CMS_DIGEST_SHA512 = 2
};

// VerifyDetached's *verificationResult out-parameter. Mirrors Plan.md 10's Valid/Invalid/
// Indeterminate + separate-technical-error convention: CMS_VERIFICATION_VALID is the only "the
// signature is cryptographically correct" outcome; CMS_VERIFICATION_TAMPERED_DATA means the
// signed digest does not match dataBuffer; CMS_VERIFICATION_UNTRUSTED_SIGNER means the signature
// itself checked out but the signer certificate did not chain to the supplied trusted root (only
// possible when VerifyDetached was given one -- see that method's own doc comment);
// CMS_VERIFICATION_TECHNICAL_ERROR means verification could not run at all (malformed CMS, etc.).
enum CmsVerificationResult
{
    CMS_VERIFICATION_VALID             = 0,
    CMS_VERIFICATION_TAMPERED_DATA     = 1,
    CMS_VERIFICATION_UNTRUSTED_SIGNER  = 2,
    CMS_VERIFICATION_TECHNICAL_ERROR   = 3
};

// Pure-virtual mirror of CCmsService's instance methods (see Certificates/CmsService.h for full
// documentation -- not repeated here to avoid drift between the two). Same DLL-boundary reasoning
// as ICertificateManager/IPgpEngine.
class ICmsService
{
public:
    virtual ~ICmsService();
             ICmsService();

    // Builds a detached PKCS#7/CMS SignedData structure (RFC 5652, CAdES-BES shape -- includes the
    // RFC 5035 signing-certificate-v2 signed attribute binding the signature to signerCertDerBuffer
    // specifically) over dataBuffer, signed by signerPrivateKeyPem. Detached: outputBuffer holds
    // only the CMS structure (signer cert + signed attributes + signature), never a copy of
    // dataBuffer itself -- VerifyDetached below needs the original dataBuffer again to check it.
    virtual int SignDetached( const unsigned char* dataBuffer, const int dataBufferSize,
                              const unsigned char* signerCertDerBuffer, const int signerCertDerBufferSize,
                              const char* signerPrivateKeyPem, const int signerPrivateKeyPemSize,
                              const CmsDigestAlgorithm digestAlgorithm,
                              const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    // Verifies cmsDerBuffer (as produced by SignDetached) against dataBuffer. When
    // trustedRootCertDerBufferSize is 0 (trustedRootCertDerBuffer may be nullptr), only the
    // cryptographic signature and digest are checked -- *verificationResult is then never
    // CMS_VERIFICATION_UNTRUSTED_SIGNER. When a trusted root is supplied, the embedded signer
    // certificate must additionally chain to it (checked via OpenSSL's own X509_verify_cert, not
    // Windows CertGetCertificateChain -- CmsService has no Windows Crypt32 dependency, unlike
    // CertificateManager).
    virtual int VerifyDetached( const unsigned char* dataBuffer, const int dataBufferSize,
                               const unsigned char* cmsDerBuffer, const int cmsDerBufferSize,
                               const unsigned char* trustedRootCertDerBuffer, const int trustedRootCertDerBufferSize,
                               int* verificationResult) = 0;

    // Reads the embedded signer certificate out of cmsDerBuffer WITHOUT verifying anything --
    // same "inspect without checking" philosophy as CPgpEngine's ListSigningKeyIds.
    virtual int ExtractSignerCertificate( const unsigned char* cmsDerBuffer, const int cmsDerBufferSize,
                                         const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) const = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

#ifndef AYCRYPTO_CMS_SERVICE_H
#define AYCRYPTO_CMS_SERVICE_H

#include "Definitions/Definitions.h"
#include "Interfaces/ICmsService.h"

#include <memory>

// Same DLL export/import boundary reasoning as Pgp/PgpEngine.h's own identical block.
#if defined(CRYPTOAPI_DLL_EXPORTS)
#define CRYPTOAPI_API __declspec(dllexport)
#elif defined(CRYPTOAPI_DLL_IMPORTS)
#define CRYPTOAPI_API __declspec(dllimport)
#else
#define CRYPTOAPI_API
#endif

namespace CryptoApiNS
{

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4251)
#pragma warning(disable: 4275)
#endif

// PKCS#7/CMS SignedData (RFC 5652), detached only -- closes Plan.md 29.4's real gap (§29.4 item 5).
// OpenSSL cms.h-backed, no Windows Crypt32 dependency (unlike CertificateManager) -- trust checks
// in VerifyDetached use OpenSSL's own X509_STORE, not Windows chain building. Stateless: every
// method takes its full input and returns its full output, no instance state (there is no
// comparable "own identity" concept here the way CPgpEngine's own-key slot has one).
class CRYPTOAPI_API CCmsService : public ICmsService
{
public:
    virtual ~CCmsService();
             CCmsService();

    // Builds a detached CMS SignedData (RFC 5652) over dataBuffer, signed with signerPrivateKeyPem/
    // signerCertDerBuffer. v1 scope simplification: does NOT include the RFC 5035
    // signing-certificate-v2 signed attribute (ICmsService.h's own doc comment still names it as
    // the design target; adding it needs OpenSSL's lower-level ESS API, deferred to a later pass)
    // -- the signingTime/content-type/message-digest attributes CMS_sign's own default set adds
    // are still present.
    int SignDetached( const unsigned char* dataBuffer, const int dataBufferSize,
                      const unsigned char* signerCertDerBuffer, const int signerCertDerBufferSize,
                      const char* signerPrivateKeyPem, const int signerPrivateKeyPemSize,
                      const CmsDigestAlgorithm digestAlgorithm,
                      const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Two-pass verification: first checks the signature/digest cryptographically without any
    // certificate trust check (CMS_NO_SIGNER_CERT_VERIFY) -- failing this always means
    // CMS_VERIFICATION_TAMPERED_DATA. Only if that passes AND a trustedRootCertDerBuffer was
    // supplied does a second pass check the embedded signer certificate chains to it; failing only
    // this second pass means CMS_VERIFICATION_UNTRUSTED_SIGNER. This two-pass shape is what lets
    // the two outcomes be told apart deterministically without parsing OpenSSL's own error queue.
    int VerifyDetached( const unsigned char* dataBuffer, const int dataBufferSize,
                       const unsigned char* cmsDerBuffer, const int cmsDerBufferSize,
                       const unsigned char* trustedRootCertDerBuffer, const int trustedRootCertDerBufferSize,
                       int* verificationResult) override;

    int ExtractSignerCertificate( const unsigned char* cmsDerBuffer, const int cmsDerBufferSize,
                                 const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) const override;

protected:

private:

};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace CryptoApiNS

#endif

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
    // signerCertDerBuffer. Includes the RFC 5035 signing-certificate-v2 signed attribute
    // (ESS_SIGNING_CERT_V2, OpenSSL's OSSL_ESS_signing_cert_v2_new_init + CMS_signed_add1_attr_by_NID,
    // added to the SignerInfo before CMS_final so it is itself covered by the signature) binding the
    // signature to signerCertDerBuffer's own SHA-256 hash + issuer/serial -- closes the gap this
    // comment used to note as deferred. digestAlgorithm only controls the message-digest algorithm;
    // the signing-certificate-v2 attribute's own hash is always SHA-256 per RFC 5035's own
    // recommendation, independent of digestAlgorithm. The signingTime/content-type/message-digest
    // attributes CMS_sign's own default set adds are still present alongside it.
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
    // Additionally, if a signing-certificate-v2 attribute is present (SignDetached above always
    // adds one; a CMS blob from elsewhere with none at all is not affected by this check),
    // OSSL_ESS_check_signing_certs confirms it actually matches the signer certificate CMS_verify
    // used -- a mismatch (cryptographically valid signature, but the ESS attribute names a
    // different certificate) reports CMS_VERIFICATION_SIGNING_CERT_MISMATCH instead of VALID,
    // checked before either pass above would report VALID.
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

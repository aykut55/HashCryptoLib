#ifndef CRYPTOAPI_ICERTIFICATE_MANAGER_H
#define CRYPTOAPI_ICERTIFICATE_MANAGER_H

#include "Definitions/Definitions.h"

namespace CryptoApiNS
{

// Key algorithm/size CreateSelfSignedCertificate/CreateCertificateRequest generate a fresh
// ephemeral key pair for (Plan.md 12.1 -- v1 scope is ephemeral keys only, not NCrypt-persistent
// ones, so no Windows CertEnroll/COM adapter is needed here; OpenSSL EVP_PKEY generation covers
// this directly).
enum CertificateKeyAlgorithm
{
    CERTIFICATE_KEY_RSA_2048   = 0,
    CERTIFICATE_KEY_RSA_3072   = 1,
    CERTIFICATE_KEY_RSA_4096   = 2,
    CERTIFICATE_KEY_ECDSA_P256 = 3,
    CERTIFICATE_KEY_ECDSA_P384 = 4
};

// Digest algorithm used by the X.509/CSR signature itself (not to be confused with a message
// digest being certified elsewhere) -- CmsService/TimestampService each declare their own,
// independent, like-named enum rather than including this header, matching IPgpEngine.h's own
// PgpFileCompressionAlgorithm vs. IPgpEngineWrapper.h's PgpCompressionAlgorithm precedent (kept
// deliberately separate so the three new interface headers never need to include each other).
enum CertificateDigestAlgorithm
{
    CERTIFICATE_DIGEST_SHA256 = 0,
    CERTIFICATE_DIGEST_SHA384 = 1,
    CERTIFICATE_DIGEST_SHA512 = 2
};

// Bit flags for CreateSelfSignedCertificate/CreateCertificateRequest/IssueCertificateFromRequest's
// keyUsageFlags parameter -- RFC 5280 section 4.2.1.3 KeyUsage bits actually used by this engine
// (a small, deliberate subset of the full nine; the rest are not needed for the certificate shapes
// this SDK builds and are left unset if the bitfield is silent about them).
enum CertificateKeyUsageFlag
{
    CERTIFICATE_KEY_USAGE_DIGITAL_SIGNATURE = 0x01,
    CERTIFICATE_KEY_USAGE_NON_REPUDIATION   = 0x02,
    CERTIFICATE_KEY_USAGE_KEY_ENCIPHERMENT  = 0x04,
    CERTIFICATE_KEY_USAGE_KEY_CERT_SIGN     = 0x08,
    CERTIFICATE_KEY_USAGE_CRL_SIGN          = 0x10
};

// Bit flags for the same three methods' extendedKeyUsageFlags parameter -- RFC 5280 section
// 4.2.1.12 EKU OIDs this engine can emit.
enum CertificateExtendedKeyUsageFlag
{
    CERTIFICATE_EKU_SERVER_AUTH       = 0x01,
    CERTIFICATE_EKU_CLIENT_AUTH       = 0x02,
    CERTIFICATE_EKU_CODE_SIGNING      = 0x04,
    CERTIFICATE_EKU_EMAIL_PROTECTION  = 0x08,
    CERTIFICATE_EKU_TIME_STAMPING     = 0x10
};

// Which Windows certificate store OpenStore below opens (Plan.md 25.2's CertificateStore).
// CERTIFICATE_STORE_MEMORY is an in-process CERT_STORE_PROV_MEMORY store -- it never touches the
// real machine's CurrentUser/LocalMachine stores, which is why the automated test suite (see
// CryptoApiTester.h RunCertificateStore* tests) only ever exercises this location, per Plan.md
// 25.8's fixture rule.
enum CertificateStoreLocation
{
    CERTIFICATE_STORE_MEMORY        = 0,
    CERTIFICATE_STORE_CURRENT_USER  = 1,
    CERTIFICATE_STORE_LOCAL_MACHINE = 2
};

// ValidateChain's revocation policy pair (Plan.md 25.6's Required/BestEffort/Disabled and
// Offline/CacheOnly/Online).
enum RevocationMode
{
    REVOCATION_MODE_REQUIRED    = 0,
    REVOCATION_MODE_BEST_EFFORT = 1,
    REVOCATION_MODE_DISABLED    = 2
};

enum RevocationNetworkMode
{
    REVOCATION_NETWORK_OFFLINE    = 0,
    REVOCATION_NETWORK_CACHE_ONLY = 1,
    REVOCATION_NETWORK_ONLINE     = 2
};

// ValidateChain's *trustResult out-parameter (Plan.md 25.6's Trusted/Untrusted/Indeterminate).
enum CertificateTrustResult
{
    CERTIFICATE_TRUST_TRUSTED        = 0,
    CERTIFICATE_TRUST_UNTRUSTED      = 1,
    CERTIFICATE_TRUST_INDETERMINATE  = 2
};

// ValidateChain's *revocationStatus out-parameter (Plan.md 25.6's Good/Revoked/Unknown/NotChecked).
enum RevocationStatus
{
    REVOCATION_STATUS_GOOD        = 0,
    REVOCATION_STATUS_REVOKED     = 1,
    REVOCATION_STATUS_UNKNOWN     = 2,
    REVOCATION_STATUS_NOT_CHECKED = 3
};

// Pure-virtual mirror of CCertificateManager's instance methods (see Certificates/
// CertificateManager.h for full documentation of each method -- not repeated here to avoid drift
// between the two). Exists for the same DLL-boundary reason IPgpEngine.h does (see that header's
// own comment) -- CCertificateManager's default constructor is the only one reachable through
// CreateCertificateManager() (see CryptoApiFactory.h), so no constructor is declared here.
class ICertificateManager
{
public:
    virtual ~ICertificateManager();
             ICertificateManager();

    // ============================================================================================
    // Inspection / conversion -- stateless, take a DER/PEM certificate buffer directly rather than
    // loading it into any instance state first (unlike CPgpEngine's own-identity/peer-key slots --
    // there is no comparable persistent "this instance's identity" concept for a certificate
    // inspection/conversion utility).
    // ============================================================================================

    virtual int GetCertificateInfoText( const unsigned char* certDerBuffer, const int certDerBufferSize,
                                        const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const = 0;

    virtual int ConvertCertificateDerToPem( const unsigned char* derBuffer, const int derBufferSize,
                                            const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const = 0;

    virtual int ConvertCertificatePemToDer( const char* pemString, const int pemStringSize,
                                            const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) const = 0;

    // ============================================================================================
    // PKCS#12 -- ImportPfx extracts the leaf certificate and its private key (v1 scope: single
    // identity, no additional chain certificates inside the PFX are extracted); ExportPfx builds a
    // new PFX from an explicit certificate + PEM private key pair.
    // ============================================================================================

    virtual int ImportPfx( const unsigned char* pfxBuffer, const int pfxBufferSize,
                           const char* password, const int passwordSize,
                           const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize,
                           const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize) = 0;

    virtual int ExportPfx( const unsigned char* certDerBuffer, const int certDerBufferSize,
                           const char* privateKeyPem, const int privateKeyPemSize,
                           const char* password, const int passwordSize,
                           const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    // ============================================================================================
    // Building -- self-signed end-entity certificate, PKCS#10 CSR, and (closing Plan.md 29.4 gap
    // #1) a CA issuing a leaf certificate from someone else's CSR. All three generate a fresh
    // ephemeral key pair and return it as a PEM private key alongside the DER certificate/CSR --
    // sanDnsNamesCsv is a comma-separated list of DNS SAN entries, may be nullptr/0-length for none.
    // ============================================================================================

    virtual int CreateSelfSignedCertificate( const char* subjectCommonName, const int subjectCommonNameSize,
                                             const char* sanDnsNamesCsv, const int sanDnsNamesCsvSize,
                                             const CertificateKeyAlgorithm keyAlgorithm, const int validityDays,
                                             const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                             const CertificateDigestAlgorithm digestAlgorithm,
                                             const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize,
                                             const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize) = 0;

    virtual int CreateCertificateRequest( const char* subjectCommonName, const int subjectCommonNameSize,
                                          const char* sanDnsNamesCsv, const int sanDnsNamesCsvSize,
                                          const CertificateKeyAlgorithm keyAlgorithm, const CertificateDigestAlgorithm digestAlgorithm,
                                          const int csrOutputCapacity, unsigned char* csrOutputBuffer, int* csrOutputSize,
                                          const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize) = 0;

    virtual int IssueCertificateFromRequest( const unsigned char* csrDerBuffer, const int csrDerBufferSize,
                                             const unsigned char* caCertDerBuffer, const int caCertDerBufferSize,
                                             const char* caPrivateKeyPem, const int caPrivateKeyPemSize,
                                             const int validityDays, const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                             const CertificateDigestAlgorithm digestAlgorithm,
                                             const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize) = 0;

    // ============================================================================================
    // Chain validation -- AddIntermediateCertificateForChainValidation accumulates intermediates
    // one call at a time (same multiplicity idiom as CPgpEngine::ImportAdditionalRecipientPublicKey,
    // chosen so a variable-length certificate list never has to cross the ABI as a raw array of
    // buffers); ValidateChain consumes and clears the accumulated list. Windows-backed
    // (CertGetCertificateChain/CertVerifyCertificateChainPolicy) so it benefits from the OS root
    // store and revocation infrastructure per Plan.md 25.6/25.7.
    // ============================================================================================

    virtual int AddIntermediateCertificateForChainValidation(const unsigned char* certDerBuffer, const int certDerBufferSize) = 0;

    virtual int ClearIntermediateCertificatesForChainValidation(void) = 0;

    virtual int ValidateChain( const unsigned char* leafCertDerBuffer, const int leafCertDerBufferSize,
                               const RevocationMode revocationMode, const RevocationNetworkMode revocationNetworkMode,
                               int* trustResult, int* revocationStatus) = 0;

    // OpenSSL-side CRL check (RFC 5280 CertificateList), complementing ValidateChain's Crypt32-
    // backed revocation checking above -- for callers holding a CRL directly (fetched out-of-band,
    // or bundled with a CA distribution) rather than relying on CryptoAPI's own CDP/OCSP fetch
    // machinery. crlIssuerCertDerBuffer/crlIssuerCertDerBufferSize may be nullptr/0 to skip the
    // CRL's own signature verification; a CRL past its own nextUpdate is treated as stale and
    // always reports REVOCATION_STATUS_UNKNOWN regardless of whether the target certificate's
    // serial number appears in it.
    virtual int CheckCertificateAgainstCrl( const unsigned char* certDerBuffer, const int certDerBufferSize,
                                            const unsigned char* crlDerBuffer, const int crlDerBufferSize,
                                            const unsigned char* crlIssuerCertDerBuffer, const int crlIssuerCertDerBufferSize,
                                            int* revocationStatus) = 0;

    // ============================================================================================
    // Store -- OpenStore/CloseStore hold one Windows certificate store open at a time (Plan.md
    // 25.2's CertificateStore); Add/Remove/Find/ImportPfxToStore operate on whichever store is
    // currently open. CERTIFICATE_STORE_MEMORY is the only location the automated test suite uses
    // (see the enum's own comment); CurrentUser/LocalMachine are real exposed capability per
    // Plan.md 25.7 but are not covered by this SDK's own automated tests (deferred to an isolated
    // test machine per 25.8).
    // ============================================================================================

    virtual int OpenStore(const CertificateStoreLocation location) = 0;
    virtual int CloseStore(void) = 0;

    virtual int AddCertificateToStore(const unsigned char* certDerBuffer, const int certDerBufferSize) = 0;
    virtual int RemoveCertificateFromStore(const unsigned char* certDerBuffer, const int certDerBufferSize) = 0;

    virtual int FindCertificateInStoreBySubject( const char* subjectSubstring, const int subjectSubstringSize,
                                                 const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int ImportPfxToStore( const unsigned char* pfxBuffer, const int pfxBufferSize,
                                  const char* password, const int passwordSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

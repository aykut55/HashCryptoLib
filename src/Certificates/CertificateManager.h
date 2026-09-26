#ifndef AYCRYPTO_CERTIFICATE_MANAGER_H
#define AYCRYPTO_CERTIFICATE_MANAGER_H

#include "Definitions/Definitions.h"
#include "Interfaces/ICertificateManager.h"

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

// C4251/C4275: see CryptoApi.h's own identical pragma block -- impl_ is private and never touched
// across the DLL boundary, and ICertificateManager (this class's base) declares no data and no
// non-inline code of its own.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4251)
#pragma warning(disable: 4275)
#endif

// X.509 certificate mechanics (self-signed/CSR/CA-issuance/PFX/DER-PEM, OpenSSL-backed -- v1 scope
// is ephemeral keys only per Plan.md 12.1, so no Windows CertEnroll/COM adapter is used) plus
// store/chain/revocation (Windows Crypt32-backed, so validation benefits from the OS root store
// and revocation infrastructure per Plan.md 25.6/25.7). One flat facade class, following the same
// real precedent CCryptoApi and CPgpEngine both actually collapsed to -- Plan.md 25.2's
// fine-grained CertificateStore/CertificateBuilder/CertificateChain/CertificateValidator class
// table was never built as separate classes anywhere in this codebase.
class CRYPTOAPI_API CCertificateManager : public ICertificateManager
{
public:
    virtual ~CCertificateManager();
             CCertificateManager();

    // ============================================================================================
    // Inspection / conversion
    // ============================================================================================

    // Multi-line "Field: value" text block -- Subject/Issuer/SerialHex/NotBefore/NotAfter/
    // SignatureAlgorithm/PublicKeyAlgorithm/SubjectAltNames/KeyUsage/ExtendedKeyUsage/
    // FingerprintSha256Hex, one per line. Deliberately a formatted text block rather than a fixed
    // ABI struct (Plan.md 25.2's CertificateInfo) or a set of individual getters -- same "buffer +
    // capacity query" convention as CPgpEngine::ExportPublicKeyArmored, chosen for the same reason:
    // no struct/STL type crosses the ABI, and a dozen separate single-field getters would be far
    // more verbose for no behavioral benefit. outputBufferCapacity=0/outputBuffer=nullptr queries
    // the required size (BUFFER_TOO_SMALL convention, same as every other buffer-output method
    // below).
    int GetCertificateInfoText( const unsigned char* certDerBuffer, const int certDerBufferSize,
                                const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const override;

    int ConvertCertificateDerToPem( const unsigned char* derBuffer, const int derBufferSize,
                                    const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const override;

    int ConvertCertificatePemToDer( const char* pemString, const int pemStringSize,
                                    const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) const override;

    // ============================================================================================
    // PKCS#12 -- v1 scope: single identity (leaf certificate + its private key), no additional
    // chain certificates inside the PFX are extracted/embedded.
    // ============================================================================================

    int ImportPfx( const unsigned char* pfxBuffer, const int pfxBufferSize,
                   const char* password, const int passwordSize,
                   const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize,
                   const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize) override;

    int ExportPfx( const unsigned char* certDerBuffer, const int certDerBufferSize,
                   const char* privateKeyPem, const int privateKeyPemSize,
                   const char* password, const int passwordSize,
                   const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // ============================================================================================
    // Building -- each generates a fresh ephemeral key pair (OpenSSL EVP_PKEY_keygen), returned as
    // a PEM private key alongside the DER certificate/CSR. sanDnsNamesCsv is a comma-separated
    // list of DNS SAN entries (e.g. "example.com,www.example.com"); may be nullptr/0-length.
    // ============================================================================================

    int CreateSelfSignedCertificate( const char* subjectCommonName, const int subjectCommonNameSize,
                                     const char* sanDnsNamesCsv, const int sanDnsNamesCsvSize,
                                     const CertificateKeyAlgorithm keyAlgorithm, const int validityDays,
                                     const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                     const CertificateDigestAlgorithm digestAlgorithm,
                                     const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize,
                                     const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize) override;

    // PKCS#10 CSR (RFC 2986), self-signed over its own fresh key pair per the CSR's own
    // requirement, NOT a CA-issued certificate -- IssueCertificateFromRequest below is the
    // CA-signing step a real CA would perform on this CSR's output.
    int CreateCertificateRequest( const char* subjectCommonName, const int subjectCommonNameSize,
                                  const char* sanDnsNamesCsv, const int sanDnsNamesCsvSize,
                                  const CertificateKeyAlgorithm keyAlgorithm, const CertificateDigestAlgorithm digestAlgorithm,
                                  const int csrOutputCapacity, unsigned char* csrOutputBuffer, int* csrOutputSize,
                                  const int keyOutputCapacity, char* keyOutputBuffer, int* keyOutputSize) override;

    // Closes Plan.md 29.4 gap #1 ("IssueCertificate" / CA role): verifies csrDerBuffer's own
    // self-signature (proof of possession of the CSR's private key), then issues a new leaf
    // certificate over the CSR's subject/public key, signed by caPrivateKeyPem, with caCertDerBuffer
    // as issuer. Does not require CA cert/key to have been produced by CreateSelfSignedCertificate
    // specifically -- any DER cert + matching PEM private key pair works.
    int IssueCertificateFromRequest( const unsigned char* csrDerBuffer, const int csrDerBufferSize,
                                     const unsigned char* caCertDerBuffer, const int caCertDerBufferSize,
                                     const char* caPrivateKeyPem, const int caPrivateKeyPemSize,
                                     const int validityDays, const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                     const CertificateDigestAlgorithm digestAlgorithm,
                                     const int certOutputCapacity, unsigned char* certOutputBuffer, int* certOutputSize) override;

    // ============================================================================================
    // Chain validation (Windows Crypt32-backed: CertGetCertificateChain +
    // CertVerifyCertificateChainPolicy, SystemTrust root store) -- AddIntermediateCertificateFor-
    // ChainValidation accumulates intermediates one call at a time (same multiplicity idiom as
    // CPgpEngine::ImportAdditionalRecipientPublicKey); ValidateChain consumes and clears the
    // accumulated list.
    // ============================================================================================

    int AddIntermediateCertificateForChainValidation(const unsigned char* certDerBuffer, const int certDerBufferSize) override;

    int ClearIntermediateCertificatesForChainValidation(void) override;

    // *trustResult and *revocationStatus are both always set on NO_ERROR (chain building/policy
    // evaluation itself ran); a technical failure (malformed leaf, chain engine error) returns a
    // non-NO_ERROR code instead and leaves both out-parameters untouched.
    int ValidateChain( const unsigned char* leafCertDerBuffer, const int leafCertDerBufferSize,
                       const RevocationMode revocationMode, const RevocationNetworkMode revocationNetworkMode,
                       int* trustResult, int* revocationStatus) override;

    // ============================================================================================
    // Store (Windows Crypt32-backed: CertOpenStore/CertAddEncodedCertificateToStore/
    // CertFindCertificateInStore/PFXImportCertStore) -- one store open at a time per instance.
    // ============================================================================================

    int OpenStore(const CertificateStoreLocation location) override;
    int CloseStore(void) override;

    int AddCertificateToStore(const unsigned char* certDerBuffer, const int certDerBufferSize) override;
    int RemoveCertificateFromStore(const unsigned char* certDerBuffer, const int certDerBufferSize) override;

    int FindCertificateInStoreBySubject( const char* subjectSubstring, const int subjectSubstringSize,
                                         const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    int ImportPfxToStore( const unsigned char* pfxBuffer, const int pfxBufferSize,
                          const char* password, const int passwordSize) override;

protected:

private:

    // OpenSSL/Windows Crypt32 types are kept out of this header so callers never need those
    // headers or include paths; only CertificateManager.cpp does (same pattern as CPgpEngine's
    // own CryptoPP-hiding Impl).
    struct Impl;
    std::unique_ptr<Impl> impl_;

};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace CryptoApiNS

#endif

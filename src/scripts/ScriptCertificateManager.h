#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_CERTIFICATE_MANAGER_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_CERTIFICATE_MANAGER_H

#include "Definitions/Definitions.h"
#include "Certificates/CertificateManager.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// Script-facing convenience facade over CCertificateManager -- same treatment as CScriptPgpEngine
// (see its own header comment): every raw buffer method gets a std::string/std::vector<unsigned
// char> counterpart that does the buffer marshaling internally and throws CScriptException instead
// of returning an ErrorCode.
//
// Two deliberate simplifications versus CCertificateManager's own C++ signature, both scoped to
// this script-facing layer only (the underlying engine_ keeps its real typed enums):
// 1. keyAlgorithm/digestAlgorithm/revocationMode/revocationNetworkMode parameters are plain `int`
//    here rather than CertificateKeyAlgorithm/CertificateDigestAlgorithm/RevocationMode/
//    RevocationNetworkMode -- CCertificateManager alone would need 4 of ICertificateManager.h's 9
//    enums registered as real script-visible enum types, and each of the 5 script engines this SDK
//    binds to has its own, non-trivial enum-registration idiom (sol2 new_enum, a custom
//    luabridge::Stack<T> specialization + pushEnumTable per engine for LuaBridge3, ChaiScript's
//    own module/type_conversion mechanism, pybind11's py::enum_) -- registering 4 enums x 5 engines
//    was judged disproportionate to the value scripts get from a real enum type over a plain int
//    with documented values (see each method's own doc comment below for the int meanings).
// 2. Methods whose C++ counterpart returns TWO outputs (a certificate/CSR buffer plus a generated
//    private key) return only the primary buffer here; the private key is stashed and retrieved via
//    GetLastPrivateKeyPem() below. This avoids needing a std::pair/tuple return type, which would
//    otherwise need its own binding boilerplate in at least LuaBridge3 (a custom Stack<> for the
//    pair type) -- every method in this class returns exactly one value, matching CScriptPgpEngine's
//    own convention.
//
// Scope: exposes conversion/inspection, self-signed/CSR/CA-issuance building, and chain validation.
// PFX import/export and the Windows-store methods (OpenStore/CloseStore/AddCertificateToStore/...)
// are NOT exposed here -- they are Windows-Crypt32-store plumbing, a poor fit for a scripting demo,
// and every other script-facing class in this SDK already keeps a reduced surface relative to its
// full C++ counterpart in at least one engine (see CScriptPgpEngineDll's own header comment, and
// LuaScriptEngineLuaBridgeLegacy.cpp's own reduced 8-method PgpEngine binding).
class CScriptCertificateManager
{
public:
    virtual ~CScriptCertificateManager();
             CScriptCertificateManager();

    std::string GetCertificateInfoText(const std::vector<unsigned char>& certDer) const;
    std::string ConvertCertificateDerToPem(const std::vector<unsigned char>& derBuffer) const;
    std::vector<unsigned char> ConvertCertificatePemToDer(const std::string& pemString) const;

    // keyAlgorithm: 0=RSA_2048, 1=RSA_3072, 2=RSA_4096, 3=ECDSA_P256, 4=ECDSA_P384 (see
    // CertificateKeyAlgorithm, ICertificateManager.h). digestAlgorithm: 0=SHA256, 1=SHA384,
    // 2=SHA512 (see CertificateDigestAlgorithm). keyUsageFlags/extendedKeyUsageFlags are the same
    // bit flags CCertificateManager's own C++ API takes (CertificateKeyUsageFlag/
    // CertificateExtendedKeyUsageFlag) -- already plain unsigned int there, so no simplification
    // needed for those two. Returns the DER certificate; the matching PEM private key is stashed,
    // retrieve it via GetLastPrivateKeyPem() before this instance generates another one.
    std::vector<unsigned char> CreateSelfSignedCertificate( const std::string& subjectCommonName, const std::string& sanDnsNamesCsv,
                                                             const int keyAlgorithm, const int validityDays,
                                                             const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                                             const int digestAlgorithm);

    // Same keyAlgorithm/digestAlgorithm meaning as CreateSelfSignedCertificate above. Returns the
    // DER CSR; the matching PEM private key is stashed the same way.
    std::vector<unsigned char> CreateCertificateRequest( const std::string& subjectCommonName, const std::string& sanDnsNamesCsv,
                                                         const int keyAlgorithm, const int digestAlgorithm);

    // Set by CreateSelfSignedCertificate/CreateCertificateRequest above -- empty string before
    // either has been called once.
    std::string GetLastPrivateKeyPem(void) const;

    // Same keyUsageFlags/extendedKeyUsageFlags/digestAlgorithm meaning as CreateSelfSignedCertificate.
    std::vector<unsigned char> IssueCertificateFromRequest( const std::vector<unsigned char>& csrDer, const std::vector<unsigned char>& caCertDer,
                                                            const std::string& caPrivateKeyPem, const int validityDays,
                                                            const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                                            const int digestAlgorithm);

    void AddIntermediateCertificateForChainValidation(const std::vector<unsigned char>& certDer);
    void ClearIntermediateCertificatesForChainValidation(void);

    // revocationMode: 0=Required, 1=BestEffort, 2=Disabled (RevocationMode). revocationNetworkMode:
    // 0=Offline, 1=CacheOnly, 2=Online (RevocationNetworkMode). Returns the trust result as int:
    // 0=Trusted, 1=Untrusted, 2=Indeterminate (CertificateTrustResult); the revocation status is
    // stashed, retrieve it via GetLastRevocationStatus().
    int ValidateChain(const std::vector<unsigned char>& leafCertDer, const int revocationMode, const int revocationNetworkMode);

    // Set by ValidateChain above: 0=Good, 1=Revoked, 2=Unknown, 3=NotChecked (RevocationStatus).
    int GetLastRevocationStatus(void) const;

protected:

private:

    // Same two-call capacity-query dance as CScriptPgpEngine's own private helpers.
    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;
    void callVoid(const char* methodName, const std::function<int(void)>& fn) const;

    CCertificateManager engine_;
    std::string lastPrivateKeyPem_;
    int lastRevocationStatus_;

};

} // namespace CryptoApiNS

#endif

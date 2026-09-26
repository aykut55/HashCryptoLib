#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_CERTIFICATE_MANAGER_DLL_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_CERTIFICATE_MANAGER_DLL_H

#include "Interfaces/ICertificateManager.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// DLL-hosted counterpart to CScriptCertificateManager -- wraps an ICertificateManager* obtained via
// CCryptoApiDllLoader::GetCertificateManagerObject() instead of owning a concrete
// CCertificateManager. Same reasoning as CScriptPgpEngineDll's own header comment: method surface
// reduced to a self-signed-certificate generation + inspection round trip, not a full mirror of
// CScriptCertificateManager. The wrapped ICertificateManager* is never owned/deleted here.
class CScriptCertificateManagerDll
{
public:
    virtual ~CScriptCertificateManagerDll();
    explicit CScriptCertificateManagerDll(ICertificateManager* manager);

    // keyAlgorithm/digestAlgorithm meaning: see CScriptCertificateManager.h's own doc comment.
    std::vector<unsigned char> CreateSelfSignedCertificate( const std::string& subjectCommonName, const int keyAlgorithm,
                                                            const int validityDays, const int digestAlgorithm);
    std::string GetLastPrivateKeyPem(void) const;
    std::string GetCertificateInfoText(const std::vector<unsigned char>& certDer) const;

protected:

private:

    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;

    ICertificateManager* manager_;
    std::string lastPrivateKeyPem_;

};

} // namespace CryptoApiNS

#endif

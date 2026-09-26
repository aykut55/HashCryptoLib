#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_CMS_SERVICE_DLL_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_CMS_SERVICE_DLL_H

#include "Interfaces/ICmsService.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// DLL-hosted counterpart to CScriptCmsService -- wraps an ICmsService* obtained via
// CCryptoApiDllLoader::GetCmsServiceObject() instead of owning a concrete CCmsService. Same
// reduced-surface reasoning as CScriptPgpEngineDll's own header comment: sign+verify round trip
// only, ExtractSignerCertificate not exposed here.
class CScriptCmsServiceDll
{
public:
    virtual ~CScriptCmsServiceDll();
    explicit CScriptCmsServiceDll(ICmsService* service);

    std::vector<unsigned char> SignDetached( const std::vector<unsigned char>& data, const std::vector<unsigned char>& signerCertDer,
                                             const std::string& signerPrivateKeyPem, const int digestAlgorithm);

    int VerifyDetached(const std::vector<unsigned char>& data, const std::vector<unsigned char>& cmsDer);

protected:

private:

    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;

    ICmsService* service_;

};

} // namespace CryptoApiNS

#endif

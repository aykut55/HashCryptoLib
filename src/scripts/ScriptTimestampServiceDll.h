#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_TIMESTAMP_SERVICE_DLL_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_TIMESTAMP_SERVICE_DLL_H

#include "Interfaces/ITimestampService.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// DLL-hosted counterpart to CScriptTimestampService -- wraps an ITimestampService* obtained via
// CCryptoApiDllLoader::GetTimestampServiceObject() instead of owning a concrete
// CTimestampService. Same reduced-surface reasoning as CScriptPgpEngineDll's own header comment:
// request-creation + the real TSA round trip + inspection, VerifyTimestampResponse not exposed here.
class CScriptTimestampServiceDll
{
public:
    virtual ~CScriptTimestampServiceDll();
    explicit CScriptTimestampServiceDll(ITimestampService* service);

    std::vector<unsigned char> CreateTimestampRequest(const std::vector<unsigned char>& digest, const int digestAlgorithm);
    std::vector<unsigned char> RequestTimestampFromTsa( const std::string& tsaUrl, const std::vector<unsigned char>& requestDer,
                                                        const int timeoutMilliseconds);
    std::string GetTimestampInfoText(const std::vector<unsigned char>& responseDer) const;

protected:

private:

    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;

    ITimestampService* service_;

};

} // namespace CryptoApiNS

#endif

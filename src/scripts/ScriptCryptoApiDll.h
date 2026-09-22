#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_CRYPTO_API_DLL_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_CRYPTO_API_DLL_H

#include "Interfaces/ICryptoApi.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// DLL-hosted counterpart to CScriptCryptoApi -- wraps an ICryptoApi* obtained via
// CCryptoApiDllLoader::GetCryptoApiObject() (i.e. CreateCryptoApi() inside a dynamically loaded
// CryptoAPI.dll, see CryptoApiFactory.h) instead of owning a concrete CCryptoApi. Deliberately a
// SEPARATE class rather than an alternate constructor on CScriptCryptoApi itself: CScriptCryptoApi
// owns a CCryptoApi BY VALUE, so even an unused alternate constructor would still force every
// translation unit that defines CScriptCryptoApi's destructor to link CCryptoApi's own destructor
// (and, transitively, the whole provider/Botan/CryptoPP/OpenSSL/Libgcrypt stack) -- exactly the
// dependency a DLL-only host (DllRunner) exists to avoid. This class never touches CCryptoApi/the
// provider stack at all, so a host compiling ONLY this file (plus the ICryptoApi/IPgpEngine/
// IPgpEngineWrapper interface headers and CryptoApiDllLoader) can drive scripting purely off the
// loaded DLL. Method surface is intentionally reduced to what DllRunner's own DLL-hosted scripting
// smoke tests exercise (Hash), not a full mirror of CScriptCryptoApi -- same "reduced surface,
// grows on demand" precedent CLuaScriptEngineLuaBridgeLegacy's own header comment documents. The
// wrapped ICryptoApi* is never owned/deleted here; the caller (via
// CCryptoApiDllLoader::DestroyCryptoApiObject()) remains responsible for it.
class CScriptCryptoApiDll
{
public:
    virtual ~CScriptCryptoApiDll();
    explicit CScriptCryptoApiDll(ICryptoApi* api);

    std::string GetVersion(void) const;
    int GetHashSize(void) const;
    std::vector<unsigned char> ComputeHashString(const std::string& input);

protected:

private:

    // Same two-call capacity-query dance as CScriptCryptoApi's own private helpers.
    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;

    ICryptoApi* api_;

};

} // namespace CryptoApiNS

#endif

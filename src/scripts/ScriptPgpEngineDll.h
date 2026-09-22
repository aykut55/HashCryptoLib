#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_PGP_ENGINE_DLL_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_PGP_ENGINE_DLL_H

#include "Interfaces/IPgpEngine.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// DLL-hosted counterpart to CScriptPgpEngine -- wraps an IPgpEngine* obtained via
// CCryptoApiDllLoader::GetPgpEngineObject() (i.e. CreatePgpEngine() inside a dynamically loaded
// CryptoAPI.dll, see CryptoApiFactory.h) instead of owning a concrete CPgpEngine. See
// ScriptCryptoApiDll.h's own header comment for why this is a genuinely separate class rather than
// an alternate constructor on CScriptPgpEngine -- same reasoning applies verbatim (CScriptPgpEngine
// owns a CPgpEngine BY VALUE; this class never touches CPgpEngine's own implementation, keeping a
// host that compiles only this file free of any CryptoPP dependency). Method surface is reduced to
// what DllRunner's own DLL-hosted scripting smoke tests exercise (a real key-generation + encrypt/
// decrypt round trip), not a full mirror of CScriptPgpEngine -- same reduced-surface precedent
// CLuaScriptEngineLuaBridgeLegacy documents. The wrapped IPgpEngine* is never owned/deleted here;
// the caller (via CCryptoApiDllLoader::DestroyPgpEngineObject()) remains responsible for it.
class CScriptPgpEngineDll
{
public:
    virtual ~CScriptPgpEngineDll();
    explicit CScriptPgpEngineDll(IPgpEngine* engine);

    void GenerateKeyPair(const std::string& userId, const std::string& password);
    std::string ExportPublicKeyArmored(void);
    void ImportPeerPublicKey(const std::string& keyBlockArmored);
    std::string EncryptStringArmored(const std::string& input);
    std::vector<unsigned char> DecryptStringArmored(const std::string& password, const std::string& input);

protected:

private:

    // Same two-call capacity-query dance as CScriptPgpEngine's own private helpers.
    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;
    void callVoid(const char* methodName, const std::function<int(void)>& fn) const;

    IPgpEngine* engine_;

};

} // namespace CryptoApiNS

#endif

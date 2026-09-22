#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_PGP_ENGINE_WRAPPER_DLL_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_PGP_ENGINE_WRAPPER_DLL_H

#include "Interfaces/IPgpEngineWrapper.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// DLL-hosted counterpart to CScriptPgpEngineWrapper -- wraps an IPgpEngineWrapper* obtained via
// CCryptoApiDllLoader::GetPgpEngineWrapperObject() (i.e. CreatePgpEngineWrapper() inside a
// dynamically loaded CryptoAPI.dll, see CryptoApiFactory.h) instead of owning a concrete
// CPgpEngineWrapper. See ScriptCryptoApiDll.h's own header comment for why this is a genuinely
// separate class rather than an alternate constructor on CScriptPgpEngineWrapper -- same reasoning
// applies verbatim. Method surface is reduced to what DllRunner's own DLL-hosted scripting smoke
// tests exercise (availability check + a real key-generation + encrypt/decrypt round trip), not a
// full mirror of CScriptPgpEngineWrapper -- same reduced-surface precedent
// CLuaScriptEngineLuaBridgeLegacy documents. The wrapped IPgpEngineWrapper* is never owned/deleted
// here; the caller (via CCryptoApiDllLoader::DestroyPgpEngineWrapperObject()) remains responsible
// for it.
class CScriptPgpEngineWrapperDll
{
public:
    virtual ~CScriptPgpEngineWrapperDll();
    explicit CScriptPgpEngineWrapperDll(IPgpEngineWrapper* wrapper);

    bool IsGnuPgAvailable(void) const;
    void GenerateKeyPair(const std::string& userId, const std::string& password);
    std::string ExportPublicKeyArmored(void);
    void ImportPeerPublicKey(const std::string& keyBlockArmored);
    std::string EncryptStringArmored(const std::string& input);
    std::vector<unsigned char> DecryptStringArmored(const std::string& password, const std::string& input);

protected:

private:

    // Same two-call capacity-query dance as CScriptPgpEngineWrapper's own private helpers.
    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;
    void callVoid(const char* methodName, const std::function<int(void)>& fn) const;

    IPgpEngineWrapper* wrapper_;

};

} // namespace CryptoApiNS

#endif

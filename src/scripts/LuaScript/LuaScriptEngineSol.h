#ifndef CRYPTOAPI_SCRIPTS_LUA_SCRIPT_LUA_SCRIPT_ENGINE_SOL_H
#define CRYPTOAPI_SCRIPTS_LUA_SCRIPT_LUA_SCRIPT_ENGINE_SOL_H

#include <sol/sol.hpp>

#include <string>

namespace CryptoApiNS
{

class CScriptCryptoApiDll;
class CScriptPgpEngineDll;
class CScriptPgpEngineWrapperDll;
class CScriptCertificateManagerDll;
class CScriptCmsServiceDll;
class CScriptTimestampServiceDll;

// Owns one sol2 Lua state and exposes CScriptCryptoApi/CScriptPgpEngine/CScriptPgpEngineWrapper
// (plus their algorithm enums) to it -- see registerBindings() in the .cpp for the exact binding
// list. RunFile/RunString only ever go through sol2's own script()/script_file() (which throw
// sol::error on a Lua-side failure when C++ exceptions are enabled, as they are in this project)
// rather than any raw lua_pcall: Lua itself is plain C and propagates its own errors via
// setjmp/longjmp, and a hand-rolled pcall boundary crossed by hand could skip C++ destructors
// (undefined behavior) -- sol2's wrappers are the only supported way to call into this state.
// open_libraries() below deliberately omits os/io/debug/package (Plan.md section 16's scripting
// policy keeps process/filesystem/native-module access closed by default for v1's trusted-script
// use case); this is a single, unsandboxed Lua state, not a security boundary against actively
// hostile scripts.
class CLuaScriptEngineSol
{
public:
    virtual ~CLuaScriptEngineSol();
             CLuaScriptEngineSol();

    void RunFile(const std::string& filePath);
    void RunString(const std::string& code);

    // Read back a Lua global left behind by RunFile/RunString -- used by CScriptEngineTester to
    // retrieve a test script's own self-checked result (e.g. a boolean "ok" flag or a string it
    // computed) without needing any callback/return-value plumbing through RunFile/RunString
    // themselves.
    bool GetGlobalBool(const std::string& name) const;
    int GetGlobalInt(const std::string& name) const;
    std::string GetGlobalString(const std::string& name) const;

    // Exposes an already-constructed CScriptCryptoApiDll/CScriptPgpEngineDll/
    // CScriptPgpEngineWrapperDll (each wrapping a DLL-hosted ICryptoApi*/IPgpEngine*/
    // IPgpEngineWrapper*, see CCryptoApiDllLoader) to this Lua state as the global "cryptoApi"/
    // "pgpEngine"/"pgpEngineWrapper", instead of a script constructing a CScriptCryptoApi/
    // CScriptPgpEngine/CScriptPgpEngineWrapper of its own via .new() (those wrap a LOCAL, owned
    // CCryptoApi/CPgpEngine/CPgpEngineWrapper -- a genuinely different type, see
    // ScriptCryptoApiDll.h's own header comment for why). The pointed-to instance's lifetime
    // remains the caller's responsibility; this engine never constructs or destroys it.
    // registerBindings() must already have run (it always has, by the time RunFile/RunString/these
    // setters are reachable -- see the constructor) so the usertype these globals resolve against
    // is already registered.
    void SetDllCryptoApi(CScriptCryptoApiDll* api);
    void SetDllPgpEngine(CScriptPgpEngineDll* engine);
    void SetDllPgpEngineWrapper(CScriptPgpEngineWrapperDll* wrapper);
    void SetDllCertificateManager(CScriptCertificateManagerDll* manager);
    void SetDllCmsService(CScriptCmsServiceDll* service);
    void SetDllTimestampService(CScriptTimestampServiceDll* service);

protected:

private:

    void registerBindings(void);

    sol::state luaState_;

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_SCRIPTS_LUA_SCRIPT_LUA_SCRIPT_ENGINE_SOL_H
#define CRYPTOAPI_SCRIPTS_LUA_SCRIPT_LUA_SCRIPT_ENGINE_SOL_H

#include <sol/sol.hpp>

#include <string>

namespace CryptoApiNS
{

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

protected:

private:

    void registerBindings(void);

    sol::state luaState_;

};

} // namespace CryptoApiNS

#endif

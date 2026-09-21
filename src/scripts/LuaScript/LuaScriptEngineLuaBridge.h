#ifndef CRYPTOAPI_SCRIPTS_LUA_SCRIPT_LUA_SCRIPT_ENGINE_LUA_BRIDGE_H
#define CRYPTOAPI_SCRIPTS_LUA_SCRIPT_LUA_SCRIPT_ENGINE_LUA_BRIDGE_H

extern "C"
{
#include <lua.h>
}

#include <string>

namespace CryptoApiNS
{

// LuaBridge3 counterpart to CLuaScriptEngine -- exposes the exact same script-facing surface
// (CScriptCryptoApi/CScriptPgpEngine/CScriptPgpEngineWrapper usertypes, the same 14 algorithm
// enums, RunFile/RunString/GetGlobalBool/GetGlobalInt/GetGlobalString) through LuaBridge3 instead
// of sol2, so the same test scripts (see CScriptEngineTester's RunLuaBridgeScript*Test methods)
// exercise a second, independent binding library over an identical facade layer. Unlike sol2,
// LuaBridge3's own Stack<std::vector<T>> specialization converts to/from a plain Lua table both
// ways (no persistent userdata registration), so no ToBytes()-style helper is needed here.
//
// LuaBridge3 does not wrap the Lua state itself (unlike sol2::state) -- this class owns a raw
// lua_State* directly (luaL_newstate/lua_close), and only opens the same safe subset of standard
// libraries CLuaScriptEngine does (base/string/math/table/coroutine), leaving os/io/debug/package
// closed by default per Plan.md section 16's scripting policy for this v1, trusted-script use case.
class CLuaScriptEngineLuaBridge
{
public:
    virtual ~CLuaScriptEngineLuaBridge();
             CLuaScriptEngineLuaBridge();

    void RunFile(const std::string& filePath);
    void RunString(const std::string& code);

    bool GetGlobalBool(const std::string& name) const;
    int GetGlobalInt(const std::string& name) const;
    std::string GetGlobalString(const std::string& name) const;

protected:

private:

    void registerBindings(void);

    lua_State* luaState_;

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_SCRIPTS_LUA_SCRIPT_LUA_SCRIPT_ENGINE_LUA_BRIDGE_LEGACY_H
#define CRYPTOAPI_SCRIPTS_LUA_SCRIPT_LUA_SCRIPT_ENGINE_LUA_BRIDGE_LEGACY_H

extern "C"
{
#include <lua.h>
}

#include <string>

namespace CryptoApiNS
{

class CScriptCryptoApiDll;
class CScriptPgpEngineDll;
class CScriptPgpEngineWrapperDll;
class CScriptCertificateManagerDll;
class CScriptCmsServiceDll;
class CScriptTimestampServiceDll;

// Classic LuaBridge (2.10, github.com/vinniefalco/LuaBridge) counterpart to
// CLuaScriptEngineLuaBridge (LuaBridge3) -- same purpose (compare a third, older binding library
// against sol2/LuaBridge3 over the identical facade layer), but LuaBridge 2.10's API is
// meaningfully more limited than either newer library:
//   - addConstructor<Signature>() takes exactly ONE function-pointer type, no overload list --
//     unlike sol2's sol::constructors<...> or LuaBridge3's addConstructor<Sig1, Sig2, ...>().
//   - addFunction(name, fn) takes exactly ONE function pointer per call, no overload list either.
//   - No built-in enum support at all (no Stack<T> fallback for enum types, no Enum<T> helper the
//     way LuaBridge3 has one).
// Because of this, registerBindings() below deliberately exposes only the DEFAULT constructor of
// each class and, for every overloaded method, only the ONE overload CScriptEngineTester's
// RunLuaBridgeLegacyScript*Test methods actually call (disambiguated with the same static_cast
// pattern CLuaScriptEngineLuaBridge uses) -- this is the full surface those tests exercise, not a
// reduced mirror of CLuaScriptEngineLuaBridge's full registration. No enum tables are registered
// either, since none of the current test scripts reference a named algorithm constant (they only
// ever construct with the default constructor and call GenerateRandomBytes with a plain int).
// Extending coverage further (other constructor overloads, enum constants) is straightforward but
// requires one differently-named static factory function per extra constructor overload and an
// explicit luabridge::Stack<T> specialization per enum type, following the pattern already used
// for the methods/overloads registered here.
class CLuaScriptEngineLuaBridgeLegacy
{
public:
    virtual ~CLuaScriptEngineLuaBridgeLegacy();
             CLuaScriptEngineLuaBridgeLegacy();

    void RunFile(const std::string& filePath);
    void RunString(const std::string& code);

    bool GetGlobalBool(const std::string& name) const;
    int GetGlobalInt(const std::string& name) const;
    std::string GetGlobalString(const std::string& name) const;

    // Exposes an already-constructed CScriptCryptoApiDll/CScriptPgpEngineDll/
    // CScriptPgpEngineWrapperDll (each wrapping a DLL-hosted ICryptoApi*/IPgpEngine*/
    // IPgpEngineWrapper*, see CCryptoApiDllLoader) to this Lua state as the global "cryptoApi"/
    // "pgpEngine"/"pgpEngineWrapper", instead of a script constructing a CScriptCryptoApi/
    // CScriptPgpEngine/CScriptPgpEngineWrapper of its own (those wrap a LOCAL, owned CCryptoApi/
    // CPgpEngine/CPgpEngineWrapper -- a genuinely different type, see ScriptCryptoApiDll.h's own
    // header comment for why). The pointed-to instance's lifetime remains the caller's
    // responsibility; this engine never constructs or destroys it. Same reasoning as
    // CLuaScriptEngineSol's own identically-named setters.
    void SetDllCryptoApi(CScriptCryptoApiDll* api);
    void SetDllPgpEngine(CScriptPgpEngineDll* engine);
    void SetDllPgpEngineWrapper(CScriptPgpEngineWrapperDll* wrapper);
    void SetDllCertificateManager(CScriptCertificateManagerDll* manager);
    void SetDllCmsService(CScriptCmsServiceDll* service);
    void SetDllTimestampService(CScriptTimestampServiceDll* service);

protected:

private:

    void registerBindings(void);

    lua_State* luaState_;

};

} // namespace CryptoApiNS

#endif

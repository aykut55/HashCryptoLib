#ifndef CRYPTOAPI_SCRIPTS_CHAI_SCRIPT_CHAI_SCRIPT_ENGINE_H
#define CRYPTOAPI_SCRIPTS_CHAI_SCRIPT_CHAI_SCRIPT_ENGINE_H

#include <chaiscript/chaiscript.hpp>

#include <string>

namespace CryptoApiNS
{

// Third scripting binding library over the same CScriptCryptoApi/CScriptPgpEngine/
// CScriptPgpEngineWrapper facade layer the Lua engines use -- see registerBindings() in the .cpp
// for the exact binding list. Unlike sol2/LuaBridge3/LuaBridge 2.10, ChaiScript needs no per-enum
// Stack<T>-style specialization at all: every value crosses the C++/script boundary as a generically
// type-erased chaiscript::Boxed_Value, so a plain C++ enum (or std::vector<unsigned char>, or any
// other copy-constructible type) works as a function argument/return with zero extra registration --
// only the individual enum VALUES need exposing, as named global constants (add_global_const), for
// scripts to reference them by name. std::vector<unsigned char> additionally gets
// chaiscript::bootstrap::standard_library::vector_type<...> registered so scripts can call
// .size()/[]/.empty() on it the same way Lua scripts index a table.
class CChaiScriptEngine
{
public:
    virtual ~CChaiScriptEngine();
             CChaiScriptEngine();

    void RunFile(const std::string& filePath);
    void RunString(const std::string& code);

    bool GetGlobalBool(const std::string& name);
    int GetGlobalInt(const std::string& name);
    std::string GetGlobalString(const std::string& name);

protected:

private:

    void registerBindings(void);

    chaiscript::ChaiScript chai_;

};

} // namespace CryptoApiNS

#endif

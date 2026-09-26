#ifndef CRYPTOAPI_SCRIPTS_PYTHON_SCRIPT_PYTHON_SCRIPT_ENGINE_H
#define CRYPTOAPI_SCRIPTS_PYTHON_SCRIPT_PYTHON_SCRIPT_ENGINE_H

#include <string>

namespace CryptoApiNS
{

class CScriptCryptoApiDll;
class CScriptPgpEngineDll;
class CScriptPgpEngineWrapperDll;
class CScriptCertificateManagerDll;
class CScriptCmsServiceDll;
class CScriptTimestampServiceDll;

// Fourth scripting binding library over the same CScriptCryptoApi/CScriptPgpEngine/
// CScriptPgpEngineWrapper facade layer the Lua/ChaiScript engines use -- see registerBindings() in
// the .cpp for the exact binding list. pybind11 embeds a full CPython interpreter (x64 ONLY -- see
// the ARCH_X64/ARCH_WIN64 guard at the top of the .cpp and 3rdParty/PYTHON_EMBED.md for exactly how
// 3rdParty\scripts\python312 was vendored). Every class/enum-value/free-function crosses the C++/
// script boundary through pybind11's own type_caster machinery: std::vector<unsigned char> converts
// to/from a plain Python list of ints automatically (pybind11/stl.h's generic list_caster; verified
// while writing this engine -- no ChaiScript-ByteVector-style extra registration turned out to be
// needed for len()/indexing/equality to work from a script), and each C++ enum gets its own
// py::enum_ with export_values() so scripts can reference e.g. PROVIDER_MICROSOFT by its bare name,
// matching ChaiScript's add_global_const flat-constant convention.
//
// Unlike ChaiScript's chaiscript::ChaiScript (a genuinely independent interpreter object per
// CChaiScriptEngine instance), CPython's Py_Initialize/Py_Finalize is PROCESS-WIDE state -- there is
// only ever one CPython interpreter per process, no matter how many CPythonScriptEngine instances
// exist. CScriptEngineTester constructs a fresh engine per test method (ten separate construction/
// destruction cycles in a single process run, exactly like every sibling engine), so a naive
// initialize-in-constructor/finalize-in-destructor would double-initialize or finalize-out-from-
// under a still-alive interpreter. This class instead tracks a process-wide static reference count
// (see the .cpp) and only actually calls py::initialize_interpreter()/py::finalize_interpreter() on
// the 0->1 / 1->0 transition -- this was flagged as the highest-risk item in this engine's design,
// and is verified by running all ten RunPythonScript*Test methods back-to-back in the same process
// (see CScriptEngineTester.cpp / Main.cpp's runTestsViaPythonScriptEngine()).
//
// No pybind11 object (py::dict/py::object/...) is kept as a class member: pybind11 explicitly
// documents that its objects must not outlive the interpreter, and this class's own destructor may
// finalize the interpreter on its 1->0 transition -- keeping a member would destroy it (running
// Py_DECREF) after that finalize already ran. Every method below instead fetches a fresh
// py::globals() (the current __main__ module dict) on each call, which is only ever done while the
// interpreter is known to still be alive.
class CPythonScriptEngine
{
public:
    virtual ~CPythonScriptEngine();
             CPythonScriptEngine();

    void RunFile(const std::string& filePath);
    void RunString(const std::string& code);

    bool GetGlobalBool(const std::string& name);
    int GetGlobalInt(const std::string& name);
    std::string GetGlobalString(const std::string& name);

    // Exposes an already-constructed CScriptCryptoApiDll/CScriptPgpEngineDll/
    // CScriptPgpEngineWrapperDll (each wrapping a DLL-hosted ICryptoApi*/IPgpEngine*/
    // IPgpEngineWrapper*, see CCryptoApiDllLoader) to this interpreter's __main__ globals as
    // "cryptoApi"/"pgpEngine"/"pgpEngineWrapper", instead of a script constructing a
    // CScriptCryptoApi/CScriptPgpEngine/CScriptPgpEngineWrapper of its own (those wrap a LOCAL,
    // owned CCryptoApi/CPgpEngine/CPgpEngineWrapper -- a genuinely different type, see
    // ScriptCryptoApiDll.h's own header comment for why). The pointed-to instance's lifetime
    // remains the caller's responsibility; this engine never constructs or destroys it. On a
    // Win32 build (no CPython vendored) these are silent no-ops, matching every other method's
    // own x64-only degradation convention above.
    void SetDllCryptoApi(CScriptCryptoApiDll* api);
    void SetDllPgpEngine(CScriptPgpEngineDll* engine);
    void SetDllPgpEngineWrapper(CScriptPgpEngineWrapperDll* wrapper);
    void SetDllCertificateManager(CScriptCertificateManagerDll* manager);
    void SetDllCmsService(CScriptCmsServiceDll* service);
    void SetDllTimestampService(CScriptTimestampServiceDll* service);

protected:

private:

    void registerBindings(void);

};

} // namespace CryptoApiNS

#endif

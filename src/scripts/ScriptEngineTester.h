#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_ENGINE_TESTER_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_ENGINE_TESTER_H

namespace CryptoApiNS
{

// Exercises CLuaScriptEngine (sol2) and CLuaScriptEngineLuaBridge (LuaBridge3) -- and, through
// them, CScriptCryptoApi/CScriptPgpEngine/CScriptPgpEngineWrapper -- with small embedded Lua
// scripts: one RunXxxTest per {binding library} x {feature area}, written out individually rather
// than merged into a shared driver (matching this repo's existing CCryptoApiTester convention of
// parallel, non-DRY test methods). Each test's own Lua script self-checks its result into a Lua
// global named "ok" (sometimes refined further after the initial assignment); the C++ side only
// reads that single boolean back via the engine's own GetGlobalBool rather than marshaling binary
// results out of Lua itself. The RunLuaBridgeScript* scripts are almost identical to their
// RunLuaScript* (sol2) counterparts, since both engines expose the same class/method/enum names to
// Lua -- the difference is only that LuaBridge3 converts plain Lua tables to/from
// std::vector<unsigned char> directly, so its scripts build byte tables with a manual
// string.byte loop instead of calling CLuaScriptEngine's sol2-specific ToBytes() helper.
class CScriptEngineTester
{
public:
    virtual ~CScriptEngineTester();
             CScriptEngineTester();

    int RunLuaScriptHashTest(void);
    int RunLuaScriptEncryptDecryptTest(void);
    int RunLuaScriptAsymmetricTest(void);
    int RunLuaScriptSignatureTest(void);
    int RunLuaScriptKeyAgreementTest(void);
    int RunLuaScriptRandomTest(void);
    int RunLuaScriptPgpKeyGenerationTest(void);
    int RunLuaScriptPgpEncryptDecryptTest(void);
    int RunLuaScriptPgpSignVerifyTest(void);
    int RunLuaScriptPgpWrapperAvailabilityTest(void);

    int RunLuaBridgeScriptHashTest(void);
    int RunLuaBridgeScriptEncryptDecryptTest(void);
    int RunLuaBridgeScriptAsymmetricTest(void);
    int RunLuaBridgeScriptSignatureTest(void);
    int RunLuaBridgeScriptKeyAgreementTest(void);
    int RunLuaBridgeScriptRandomTest(void);
    int RunLuaBridgeScriptPgpKeyGenerationTest(void);
    int RunLuaBridgeScriptPgpEncryptDecryptTest(void);
    int RunLuaBridgeScriptPgpSignVerifyTest(void);
    int RunLuaBridgeScriptPgpWrapperAvailabilityTest(void);

    int RunLuaBridgeLegacyScriptHashTest(void);
    int RunLuaBridgeLegacyScriptEncryptDecryptTest(void);
    int RunLuaBridgeLegacyScriptAsymmetricTest(void);
    int RunLuaBridgeLegacyScriptSignatureTest(void);
    int RunLuaBridgeLegacyScriptKeyAgreementTest(void);
    int RunLuaBridgeLegacyScriptRandomTest(void);
    int RunLuaBridgeLegacyScriptPgpKeyGenerationTest(void);
    int RunLuaBridgeLegacyScriptPgpEncryptDecryptTest(void);
    int RunLuaBridgeLegacyScriptPgpSignVerifyTest(void);
    int RunLuaBridgeLegacyScriptPgpWrapperAvailabilityTest(void);

    int RunChaiScriptHashTest(void);
    int RunChaiScriptEncryptDecryptTest(void);
    int RunChaiScriptAsymmetricTest(void);
    int RunChaiScriptSignatureTest(void);
    int RunChaiScriptKeyAgreementTest(void);
    int RunChaiScriptRandomTest(void);
    int RunChaiScriptPgpKeyGenerationTest(void);
    int RunChaiScriptPgpEncryptDecryptTest(void);
    int RunChaiScriptPgpSignVerifyTest(void);
    int RunChaiScriptPgpWrapperAvailabilityTest(void);

    int RunPythonScriptHashTest(void);
    int RunPythonScriptEncryptDecryptTest(void);
    int RunPythonScriptAsymmetricTest(void);
    int RunPythonScriptSignatureTest(void);
    int RunPythonScriptKeyAgreementTest(void);
    int RunPythonScriptRandomTest(void);
    int RunPythonScriptPgpKeyGenerationTest(void);
    int RunPythonScriptPgpEncryptDecryptTest(void);
    int RunPythonScriptPgpSignVerifyTest(void);
    int RunPythonScriptPgpWrapperAvailabilityTest(void);

protected:

private:

};

} // namespace CryptoApiNS

#endif

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

    // C++-calls-INTO-script direction: EncryptFileWithProgress's onProgress parameter is a script
    // function, called once per chunk from inside CCryptoApi's own C++ file loop -- the reverse of
    // every other test in this file (which are all script-calls-C++). See ScriptProgressCallback's
    // own comment (ScriptCryptoApi.h) for the underlying mechanism.
    int RunLuaScriptProgressCallbackTest(void);

    // Self-signed certificate generation (CertificateManager) + detached CMS sign/verify
    // (CmsService) + RFC 3161 request creation (TimestampService, no network call -- see this
    // method's own .cpp comment for why), all from one Lua script via sol2 -- see
    // CScriptCertificateManager/CScriptCmsService/CScriptTimestampService's own header comments
    // for why algorithm/mode parameters are plain ints here rather than named enum constants.
    int RunLuaScriptCertificateTest(void);

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

    int RunLuaBridgeScriptProgressCallbackTest(void);

    // LuaBridge3 mirror of RunLuaScriptCertificateTest -- manual string.byte table building
    // instead of ToBytes(), same reasoning as every other RunLuaBridgeScript*Test.
    int RunLuaBridgeScriptCertificateTest(void);

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

    int RunLuaBridgeLegacyScriptProgressCallbackTest(void);

    // LuaBridge 2.10 mirror of RunLuaScriptCertificateTest -- none of CertificateManager/
    // CmsService/TimestampService's methods are overloaded, so unlike CScriptPgpEngine/
    // CScriptPgpEngineWrapper this needed no reduced surface (see
    // LuaScriptEngineLuaBridgeLegacy.cpp's own comment on the CertificateManager/CmsService/
    // TimestampService registration block).
    int RunLuaBridgeLegacyScriptCertificateTest(void);

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

    int RunChaiScriptProgressCallbackTest(void);

    // ChaiScript mirror of RunLuaScriptCertificateTest.
    int RunChaiScriptCertificateTest(void);

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

    int RunPythonScriptProgressCallbackTest(void);

    // pybind11 mirror of RunLuaScriptCertificateTest.
    int RunPythonScriptCertificateTest(void);

protected:

private:

};

} // namespace CryptoApiNS

#endif

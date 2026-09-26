#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <fstream>

// ChaiScriptEngine.h pulls in <chaiscript/chaiscript.hpp>, which transitively includes
// <Windows.h> -- WinBase.h defines EncryptFile/DecryptFile as UNICODE-dependent macros for the
// real Win32 EFS functions (EncryptFileW/DecryptFileW under this project's CharacterSet=Unicode
// setting) and NO_ERROR as a WinError.h macro (0L). CryptoApi.h/CryptoApiTester.h/Pgp/Scripts
// below declare members and CryptoApiNS enumerators of those exact names (CCryptoApi::EncryptFile/
// DecryptFile, CryptoApiNS::NO_ERROR); parsed after an unguarded Windows.h expansion, those
// declarations would get silently macro-substituted, mismatching the real symbol names already
// compiled into CryptoAPI_static.lib (LNK2019) -- same collision and same fix DllRunner/Main.cpp's
// own top-of-file comment documents in full. Including ChaiScriptEngine.h FIRST lets Windows.h's
// own include guard absorb every later transitive pull (PythonScriptEngine.h's Python.h among
// them) as a no-op, so the explicit undefs below stay in effect for the rest of this file.
#include "Scripts/ChaiScript/ChaiScriptEngine.h"

#ifdef NO_ERROR
#undef NO_ERROR
#endif
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif

#include "CryptoApi.h"
#include "CryptoApiTester.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"

#include "Scripts/ScriptCryptoApi.h"
#include "Scripts/ScriptPgpEngine.h"
#include "Scripts/ScriptPgpEngineWrapper.h"
#include "Scripts/LuaScript/LuaScriptEngineSol.h"
#include "Scripts/LuaScript/LuaScriptEngineLuaBridge.h"
#include "Scripts/LuaScript/LuaScriptEngineLuaBridgeLegacy.h"
#include "Scripts/PythonScript/PythonScriptEngine.h"

// Linked here instead of via the project's Linker > Input > Additional Dependencies setting;
// the search path (LibBuilder's per-platform output directory) still comes from the project's
// Additional Library Directories, this only supplies the library's name.
#pragma comment(lib, "CryptoAPI_static.lib")

int main()
{
    try
    {
        std::cout << "Hello World!\n";
        std::cout << std::endl;

        CryptoApiNS::CCryptoApi cryptoApi;

        std::cout << "CryptoAPI version: " << cryptoApi.GetVersion() << std::endl;
        std::cout << std::endl;

        // IPgpEngine/IPgpEngineWrapper exercised through their interface pointers even though
        // this is a static link (no DLL boundary to cross) -- proves the new interface layer
        // itself (CPgpEngine : public IPgpEngine / CPgpEngineWrapper : public IPgpEngineWrapper,
        // see Pgp/PgpEngine.h/PgpEngineWrapper.h) compiles and dispatches correctly on its own,
        // independent of DllRunner's DLL-boundary round trip (see DllRunner/Main.cpp). Same
        // Alice-to-Alice self-contained round trip: GenerateKeyPair, export this instance's own
        // public key, re-import it as its own peer, encrypt, decrypt, compare.
        {
            CryptoApiNS::IPgpEngine* pPgpEngine = new CryptoApiNS::CPgpEngine();

            const char* userId = "LibRunner Test <librunner@example.com>";
            const char* password = "LibRunnerTestPassword123";
            const char* plaintext = "Hello from LibRunner via IPgpEngine!";

            int rc = pPgpEngine->GenerateKeyPair(userId, static_cast<int>(strlen(userId)),
                                                password, static_cast<int>(strlen(password)));

            if (rc == CryptoApiNS::NO_ERROR)
            {
                int pubKeySize = 0;
                pPgpEngine->ExportPublicKeyArmored(0, nullptr, &pubKeySize);

                std::vector<char> pubKeyBuffer(pubKeySize);
                pPgpEngine->ExportPublicKeyArmored(pubKeySize, pubKeyBuffer.data(), &pubKeySize);

                pPgpEngine->ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(pubKeyBuffer.data()), pubKeySize);

                int cipherSize = 0;
                pPgpEngine->EncryptStringArmored(plaintext, static_cast<int>(strlen(plaintext)), 0, nullptr, &cipherSize);

                std::vector<char> cipherBuffer(cipherSize);
                pPgpEngine->EncryptStringArmored(plaintext, static_cast<int>(strlen(plaintext)), cipherSize, cipherBuffer.data(), &cipherSize);

                int plainSize = 0;
                pPgpEngine->DecryptStringArmored(password, static_cast<int>(strlen(password)),
                                                cipherBuffer.data(), cipherSize, 0, nullptr, &plainSize);

                std::vector<unsigned char> plainBuffer(plainSize);
                pPgpEngine->DecryptStringArmored(password, static_cast<int>(strlen(password)),
                                                cipherBuffer.data(), cipherSize, plainSize, plainBuffer.data(), &plainSize);

                std::string decrypted(reinterpret_cast<char*>(plainBuffer.data()), plainSize);

                std::cout << "IPgpEngine (static link) EncryptStringArmored/DecryptStringArmored round trip: "
                          << (decrypted == plaintext ? "PASSED" : "FAILED") << std::endl;
            }
            else
            {
                std::cout << "IPgpEngine::GenerateKeyPair failed, rc=" << rc << std::endl;
            }

            delete pPgpEngine;
        }

        {
            // Two separate engine instances (each its own isolated --homedir), not a self-import:
            // gpg's own "--import" reports a key already present in the keyring (as it would be
            // right after this same instance's own GenerateKeyPair) as "unchanged" rather than
            // "IMPORTED", which importPeerPublicKeyCommon (Pgp/PgpEngineWrapper.cpp) treats as
            // INVALID_DATA, not success -- verified directly against this machine's gpg.exe while
            // wiring this test up. Matches CCryptoApiTester::RunPgpWrapperEncryptDecryptTest's own
            // Alice/Bob pattern; see DllRunner/Main.cpp for the identical DLL-boundary version.
            CryptoApiNS::IPgpEngineWrapper* pAlice = new CryptoApiNS::CPgpEngineWrapper();
            CryptoApiNS::IPgpEngineWrapper* pBob = new CryptoApiNS::CPgpEngineWrapper();

            if (pAlice->IsGnuPgAvailable())
            {
                const char* aliceUserId = "LibRunner Alice <librunner-alice@example.com>";
                const char* alicePassword = "LibRunnerAlicePassword123";
                const char* bobUserId = "LibRunner Bob <librunner-bob@example.com>";
                const char* bobPassword = "LibRunnerBobPassword123";
                const char* plaintext = "Hello Bob from LibRunner via IPgpEngineWrapper!";

                int rc = pAlice->GenerateKeyPair(aliceUserId, static_cast<int>(strlen(aliceUserId)),
                                                alicePassword, static_cast<int>(strlen(alicePassword)));
                int rcBob = (rc == CryptoApiNS::NO_ERROR)
                    ? pBob->GenerateKeyPair(bobUserId, static_cast<int>(strlen(bobUserId)),
                                            bobPassword, static_cast<int>(strlen(bobPassword)))
                    : rc;

                if (rc == CryptoApiNS::NO_ERROR && rcBob == CryptoApiNS::NO_ERROR)
                {
                    int alicePubKeySize = 0;
                    pAlice->ExportPublicKeyArmored(0, nullptr, &alicePubKeySize);
                    std::vector<char> alicePubKeyBuffer(alicePubKeySize);
                    pAlice->ExportPublicKeyArmored(alicePubKeySize, alicePubKeyBuffer.data(), &alicePubKeySize);

                    int bobPubKeySize = 0;
                    pBob->ExportPublicKeyArmored(0, nullptr, &bobPubKeySize);
                    std::vector<char> bobPubKeyBuffer(bobPubKeySize);
                    pBob->ExportPublicKeyArmored(bobPubKeySize, bobPubKeyBuffer.data(), &bobPubKeySize);

                    pAlice->ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(bobPubKeyBuffer.data()), bobPubKeySize);
                    pBob->ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(alicePubKeyBuffer.data()), alicePubKeySize);

                    int cipherSize = 0;
                    pAlice->EncryptStringArmored(plaintext, static_cast<int>(strlen(plaintext)), 0, nullptr, &cipherSize);

                    std::vector<char> cipherBuffer(cipherSize);
                    pAlice->EncryptStringArmored(plaintext, static_cast<int>(strlen(plaintext)), cipherSize, cipherBuffer.data(), &cipherSize);

                    int plainSize = 0;
                    pBob->DecryptStringArmored(bobPassword, static_cast<int>(strlen(bobPassword)),
                                                cipherBuffer.data(), cipherSize, 0, nullptr, &plainSize);

                    std::vector<unsigned char> plainBuffer(plainSize);
                    pBob->DecryptStringArmored(bobPassword, static_cast<int>(strlen(bobPassword)),
                                                cipherBuffer.data(), cipherSize, plainSize, plainBuffer.data(), &plainSize);

                    std::string decrypted(reinterpret_cast<char*>(plainBuffer.data()), plainSize);

                    std::cout << "IPgpEngineWrapper (static link) Alice->Bob EncryptStringArmored/DecryptStringArmored round trip: "
                              << (decrypted == plaintext ? "PASSED" : "FAILED") << std::endl;
                }
                else
                {
                    std::cout << "IPgpEngineWrapper::GenerateKeyPair failed, alice rc=" << rc << " bob rc=" << rcBob << std::endl;
                }
            }
            else
            {
                std::cout << "IPgpEngineWrapper: GnuPG not available, skipping round trip." << std::endl;
            }

            delete pAlice;
            delete pBob;
        }

        // Scripting via the statically-linked facade: fresh CScriptCryptoApi/CScriptPgpEngine
        // instances (each owning its own concrete CCryptoApi/CPgpEngine BY VALUE, no DLL boundary
        // and no loader involved -- see ScriptCryptoApiDll.h's own header comment for why that
        // class family exists only for the DLL-hosted case), run through all 5 script engines. Same
        // hash + Alice/Bob PGP round trip pattern DllRunner/Main.cpp's own DLL-hosted scripting
        // section uses, adapted to the local facade's own constructor syntax (CryptoApi.new()/
        // PgpEngine.new() for sol2, CryptoApi()/PgpEngine() for the rest -- see
        // ScriptEngineTester.cpp's own per-engine test scripts for this same syntax difference).
        {
            std::cout << std::endl;

            const char* luaScript =
                "local api = CryptoApi.new()\n"
                "local hashResult = api:ComputeHashString(\"hello\")\n"
                "local hashOk = (#hashResult == api:GetHashSize())\n"
                "\n"
                "local alice = PgpEngine.new()\n"
                "local bob = PgpEngine.new()\n"
                "alice:GenerateKeyPair(\"LibRunner Alice <librunner-alice@example.com>\", \"LibRunnerAlicePw123\")\n"
                "bob:GenerateKeyPair(\"LibRunner Bob <librunner-bob@example.com>\", \"LibRunnerBobPw123\")\n"
                "alice:ImportPeerPublicKey(bob:ExportPublicKeyArmored())\n"
                "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
                "local plaintext = \"Hello Bob, this message was encrypted entirely from LibRunner Lua!\"\n"
                "local ciphertext = alice:EncryptStringArmored(plaintext)\n"
                "local decryptedBytes = bob:DecryptStringArmored(\"LibRunnerBobPw123\", ciphertext)\n"
                "local chars = {}\n"
                "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
                "local pgpOk = (table.concat(chars) == plaintext)\n"
                "\n"
                "ok = hashOk and pgpOk\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(luaScript);
                std::cout << "Static-link scripting (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* luaBridgeScript =
                "local api = CryptoApi()\n"
                "local hashResult = api:ComputeHashString(\"hello\")\n"
                "local hashOk = (#hashResult == api:GetHashSize())\n"
                "\n"
                "local alice = PgpEngine()\n"
                "local bob = PgpEngine()\n"
                "alice:GenerateKeyPair(\"LibRunner Alice <librunner-alice@example.com>\", \"LibRunnerAlicePw123\")\n"
                "bob:GenerateKeyPair(\"LibRunner Bob <librunner-bob@example.com>\", \"LibRunnerBobPw123\")\n"
                "alice:ImportPeerPublicKey(bob:ExportPublicKeyArmored())\n"
                "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
                "local plaintext = \"Hello Bob, this message was encrypted entirely from LibRunner LuaBridge!\"\n"
                "local ciphertext = alice:EncryptStringArmored(plaintext)\n"
                "local decryptedBytes = bob:DecryptStringArmored(\"LibRunnerBobPw123\", ciphertext)\n"
                "local chars = {}\n"
                "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
                "local pgpOk = (table.concat(chars) == plaintext)\n"
                "\n"
                "ok = hashOk and pgpOk\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(luaBridgeScript);
                std::cout << "Static-link scripting (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(luaBridgeScript);
                std::cout << "Static-link scripting (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* chaiScript =
                "var api = CryptoApi();\n"
                "var hashResult = api.ComputeHashString(\"hello\");\n"
                "var hashOk = (hashResult.size() == api.GetHashSize());\n"
                "\n"
                "var alice = PgpEngine();\n"
                "var bob = PgpEngine();\n"
                "alice.GenerateKeyPair(\"LibRunner Alice <librunner-alice@example.com>\", \"LibRunnerAlicePw123\");\n"
                "bob.GenerateKeyPair(\"LibRunner Bob <librunner-bob@example.com>\", \"LibRunnerBobPw123\");\n"
                "alice.ImportPeerPublicKey(bob.ExportPublicKeyArmored());\n"
                "bob.ImportPeerPublicKey(alice.ExportPublicKeyArmored());\n"
                "var plaintext = \"Hello Bob, this message was encrypted entirely from LibRunner ChaiScript!\";\n"
                "var ciphertext = alice.EncryptStringArmored(plaintext);\n"
                "var decryptedBytes = bob.DecryptStringArmored(\"LibRunnerBobPw123\", ciphertext);\n"
                "var decryptedText = ToStringFromBytes(decryptedBytes);\n"
                "var pgpOk = (decryptedText == plaintext);\n"
                "\n"
                "global ok = (hashOk && pgpOk);\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(chaiScript);
                std::cout << "Static-link scripting (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* pythonScript =
                "api = CryptoApi()\n"
                "hashResult = api.ComputeHashString(\"hello\")\n"
                "hashOk = (len(hashResult) == api.GetHashSize())\n"
                "\n"
                "alice = PgpEngine()\n"
                "bob = PgpEngine()\n"
                "alice.GenerateKeyPair(\"LibRunner Alice <librunner-alice@example.com>\", \"LibRunnerAlicePw123\")\n"
                "bob.GenerateKeyPair(\"LibRunner Bob <librunner-bob@example.com>\", \"LibRunnerBobPw123\")\n"
                "alice.ImportPeerPublicKey(bob.ExportPublicKeyArmored())\n"
                "bob.ImportPeerPublicKey(alice.ExportPublicKeyArmored())\n"
                "plaintext = \"Hello Bob, this message was encrypted entirely from LibRunner Python!\"\n"
                "ciphertext = alice.EncryptStringArmored(plaintext)\n"
                "decryptedBytes = bob.DecryptStringArmored(\"LibRunnerBobPw123\", ciphertext)\n"
                "decryptedText = ToStringFromBytes(decryptedBytes)\n"
                "pgpOk = (decryptedText == plaintext)\n"
                "\n"
                "ok = hashOk and pgpOk\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(pythonScript);
                std::cout << "Static-link scripting (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting (Python): FAILED exception " << ex.what() << std::endl;
            }

            // Progress-callback round trip (C++-calls-INTO-script direction, see
            // ScriptProgressCallback.h's own comment): a script-supplied onProgress function gets
            // called once per chunk during EncryptFileWithProgress, proving the same interop
            // AppBuilder's own RunXxxScriptProgressCallbackTest already verifies works identically
            // against the statically-linked local facade here. File size (5120 bytes = 5 chunks of
            // FILE_CHUNK_SIZE=1024) matches ScriptEngineTester.cpp's own convention.
            const char* progressInputPath = "librunner_progress_test_in.bin";
            const char* progressEncPath = "librunner_progress_test_enc.bin";

            {
                std::vector<unsigned char> progressTestData(5120, 'A');
                std::ofstream progressInputFile(progressInputPath, std::ios::binary);
                progressInputFile.write(reinterpret_cast<const char*>(progressTestData.data()), static_cast<std::streamsize>(progressTestData.size()));
            }

            // sol2/Lua only: a second level of C++-calls-INTO-script nesting on top of the
            // per-chunk onProgress callback -- inside onProgress itself, the script calls the bound
            // C++ function OnProgress (LuaScriptEngineSol.cpp's own registerBindings), which
            // immediately calls back into a SECOND script-defined function (innerCallback), then
            // unwinds all the way back to the C++ file loop. Only registered for sol2 (see that
            // binding's own comment); proves the round trip is not limited to one fixed callback
            // slot. Same demonstration AppBuilder's RunLuaScriptProgressCallbackTest already proves,
            // now shown working against a statically-linked LibRunner build too.
            const char* progressLuaScript =
                "local api = CryptoApi.new()\n"
                "callCount = 0\n"
                "lastCurrentByte = 0\n"
                "innerCallCount = 0\n"
                "local function innerCallback()\n"
                "    innerCallCount = innerCallCount + 1\n"
                "end\n"
                "local function onProgress(currentByte, totalByte, percentage)\n"
                "    callCount = callCount + 1\n"
                "    lastCurrentByte = currentByte\n"
                "    OnProgress(innerCallback)\n"
                "    return true\n"
                "end\n"
                "api:EncryptFileWithProgress(\"librunnerprogresstest\", \"librunner_progress_test_in.bin\", \"librunner_progress_test_enc.bin\", onProgress)\n"
                "ok = (callCount >= 3) and (lastCurrentByte == 5120) and (innerCallCount == callCount)\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(progressLuaScript);
                std::cout << "Static-link progress callback (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED")
                          << " callCount=" << luaEngine.GetGlobalInt("callCount") << " innerCallCount=" << luaEngine.GetGlobalInt("innerCallCount") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link progress callback (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* progressLuaBridgeScript =
                "local api = CryptoApi()\n"
                "callCount = 0\n"
                "lastCurrentByte = 0\n"
                "local function onProgress(currentByte, totalByte, percentage)\n"
                "    callCount = callCount + 1\n"
                "    lastCurrentByte = currentByte\n"
                "    return true\n"
                "end\n"
                "api:EncryptFileWithProgress(\"librunnerprogresstest\", \"librunner_progress_test_in.bin\", \"librunner_progress_test_enc.bin\", onProgress)\n"
                "ok = (callCount >= 3) and (lastCurrentByte == 5120)\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(progressLuaBridgeScript);
                std::cout << "Static-link progress callback (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << " callCount=" << luaBridgeEngine.GetGlobalInt("callCount") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link progress callback (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(progressLuaBridgeScript);
                std::cout << "Static-link progress callback (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << " callCount=" << luaBridgeLegacyEngine.GetGlobalInt("callCount") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link progress callback (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* progressChaiScript =
                "var api = CryptoApi();\n"
                "global callCount = 0;\n"
                "global lastCurrentByte = 0;\n"
                "def onProgress(currentByte, totalByte, percentage) {\n"
                "    callCount = callCount + 1;\n"
                "    lastCurrentByte = currentByte;\n"
                "    return true;\n"
                "}\n"
                "api.EncryptFileWithProgress(\"librunnerprogresstest\", \"librunner_progress_test_in.bin\", \"librunner_progress_test_enc.bin\", onProgress);\n"
                "global ok = (callCount >= 3) && (lastCurrentByte == 5120);\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(progressChaiScript);
                std::cout << "Static-link progress callback (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << " callCount=" << chaiEngine.GetGlobalInt("callCount") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link progress callback (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* progressPythonScript =
                "api = CryptoApi()\n"
                "callCount = 0\n"
                "lastCurrentByte = 0\n"
                "def onProgress(currentByte, totalByte, percentage):\n"
                "    global callCount, lastCurrentByte\n"
                "    callCount = callCount + 1\n"
                "    lastCurrentByte = currentByte\n"
                "    return True\n"
                "api.EncryptFileWithProgress(\"librunnerprogresstest\", \"librunner_progress_test_in.bin\", \"librunner_progress_test_enc.bin\", onProgress)\n"
                "ok = (callCount >= 3) and (lastCurrentByte == 5120)\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(progressPythonScript);
                std::cout << "Static-link progress callback (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << " callCount=" << pythonEngine.GetGlobalInt("callCount") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link progress callback (Python): FAILED exception " << ex.what() << std::endl;
            }

            std::remove(progressInputPath);
            std::remove(progressEncPath);
        }

        std::cout << std::endl;

        CryptoApiNS::CCryptoApiTester cryptoApiTester;

        cryptoApiTester.Run();

#if 0
        cryptoApiTester.RunEncryptDecryptFileTest();

        cryptoApiTester.RunEncryptDecryptStringTest();

        cryptoApiTester.RunEncryptDecryptBufferTest();

        cryptoApiTester.RunEncryptDecryptBytesTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderEncryptDecryptFileTest();

        cryptoApiTester.RunMicrosoftProviderEncryptDecryptStringTest();

        cryptoApiTester.RunMicrosoftProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunMicrosoftProviderEncryptDecryptBytesTest();

        cryptoApiTester.RunCryptoPPProviderEncryptDecryptFileTest();

        cryptoApiTester.RunCryptoPPProviderEncryptDecryptStringTest();

        cryptoApiTester.RunCryptoPPProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunCryptoPPProviderEncryptDecryptBytesTest();

        cryptoApiTester.RunBotanProviderEncryptDecryptFileTest();

        cryptoApiTester.RunBotanProviderEncryptDecryptStringTest();

        cryptoApiTester.RunBotanProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunBotanProviderEncryptDecryptBytesTest();

        cryptoApiTester.RunOpenSslProviderEncryptDecryptFileTest();

        cryptoApiTester.RunOpenSslProviderEncryptDecryptStringTest();

        cryptoApiTester.RunOpenSslProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunOpenSslProviderEncryptDecryptBytesTest();

        cryptoApiTester.RunLibgcryptProviderEncryptDecryptFileTest();

        cryptoApiTester.RunLibgcryptProviderEncryptDecryptStringTest();

        cryptoApiTester.RunLibgcryptProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunLibgcryptProviderEncryptDecryptBytesTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderAsymmetricTest();

        cryptoApiTester.RunCryptoPPProviderAsymmetricTest();

        cryptoApiTester.RunBotanProviderAsymmetricTest();

        cryptoApiTester.RunOpenSslProviderAsymmetricTest();

        cryptoApiTester.RunLibgcryptProviderAsymmetricTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderLegacyTest();

        cryptoApiTester.RunCryptoPPProviderLegacyTest();

        cryptoApiTester.RunBotanProviderLegacyTest();

        cryptoApiTester.RunOpenSslProviderLegacyTest();

        cryptoApiTester.RunLibgcryptProviderLegacyTest();
#endif

#if 0
        cryptoApiTester.RunLegacyAlgorithmsTest();  // Uzun surdu
#endif

#if 0
        cryptoApiTester.RunEncryptStringMultilingualTest();

        cryptoApiTester.RunPrimitiveDataTest();

        cryptoApiTester.RunPrimitiveArrayDataTest();

        cryptoApiTester.RunVectorDataTest();

        cryptoApiTester.RunVectorWideStringDataTest();
#endif

#if 0
        cryptoApiTester.RunProviderFactoryTest();

        cryptoApiTester.RunProviderFactoryFileTest();

        cryptoApiTester.RunProviderFactoryStringTest();

        cryptoApiTester.RunProviderFactoryBufferTest();

        cryptoApiTester.RunProviderFactoryBytesTest();
#endif

#if 0
        cryptoApiTester.RunEncryptDecryptFileTestNonBlocking();

        cryptoApiTester.RunEncryptDecryptStringTestNonBlocking();

        cryptoApiTester.RunEncryptDecryptBufferTestNonBlocking();

        cryptoApiTester.RunEncryptDecryptBytesTestNonBlocking();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderAllAlgorithmsTest();

        cryptoApiTester.RunCryptoPPProviderAllAlgorithmsTest();

        cryptoApiTester.RunBotanProviderAllAlgorithmsTest();

        cryptoApiTester.RunOpenSslProviderAllAlgorithmsTest();

        cryptoApiTester.RunLibgcryptProviderAllAlgorithmsTest();
#endif

#if 0
        cryptoApiTester.RunEncodingUtilsTest();

        cryptoApiTester.RunAesConfigurationDemoTest();  // Uzun surdu

        cryptoApiTester.RunPaddingUtilsTest();
#endif

#if 0
        cryptoApiTester.RunEncryptHexBase64CompositionTest();

        cryptoApiTester.RunEncryptFileHexBase64CompositionTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderHashTest();

        cryptoApiTester.RunCryptoPPProviderHashTest();

        cryptoApiTester.RunBotanProviderHashTest();

        cryptoApiTester.RunOpenSslProviderHashTest();

        cryptoApiTester.RunLibgcryptProviderHashTest();
#endif

#if 0
        cryptoApiTester.RunHashAlgorithmsTest();
#endif

#if 0
        cryptoApiTester.RunHashFileTest();

        cryptoApiTester.RunHashStringTest();

        cryptoApiTester.RunHashBufferTest();

        cryptoApiTester.RunHashBytesTest();
#endif

#if 0
        cryptoApiTester.RunProviderFactoryHashTest();

        cryptoApiTester.RunProviderFactoryHashFileTest();

        cryptoApiTester.RunProviderFactoryHashStringTest();

        cryptoApiTester.RunProviderFactoryHashBufferTest();

        cryptoApiTester.RunProviderFactoryHashBytesTest();
#endif

#if 0
        cryptoApiTester.RunHashHexBase64CompositionTest();

        cryptoApiTester.RunHashFileHexBase64CompositionTest();
#endif

#if 0
        cryptoApiTester.RunHashFileTestNonBlocking();

        cryptoApiTester.RunHashStringTestNonBlocking();

        cryptoApiTester.RunHashBufferTestNonBlocking();

        cryptoApiTester.RunHashBytesTestNonBlocking();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderSignatureTest();

        cryptoApiTester.RunCryptoPPProviderSignatureTest();

        cryptoApiTester.RunBotanProviderSignatureTest();        // Uzun surdu

        cryptoApiTester.RunOpenSslProviderSignatureTest();

        cryptoApiTester.RunLibgcryptProviderSignatureTest();

        cryptoApiTester.RunSignatureAlgorithmsTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderKeyAgreementTest();

        cryptoApiTester.RunCryptoPPProviderKeyAgreementTest();

        cryptoApiTester.RunBotanProviderKeyAgreementTest();

        cryptoApiTester.RunOpenSslProviderKeyAgreementTest();

        cryptoApiTester.RunLibgcryptProviderKeyAgreementTest();

        cryptoApiTester.RunKeyAgreementAlgorithmsTest();
#endif

#if 0
        cryptoApiTester.RunAESTests();  // Uzun surdu
#endif

#if 0
        cryptoApiTester.RunSharedInstanceTest();
#endif

#if 0
        cryptoApiTester.RunRandomAlgorithmsTest();
#endif

#if 1
        cryptoApiTester.RunPgpKeyGenerationTest();

        cryptoApiTester.RunPgpEncryptDecryptTest();

        cryptoApiTester.RunPgpSignVerifyTest();

        cryptoApiTester.RunPgpClearSignTest();

        cryptoApiTester.RunPgpArmorTest();

        cryptoApiTester.RunPgpAliceBobTest();

        cryptoApiTester.RunPgpFileEncryptDecryptTest();

        cryptoApiTester.RunPgpFileSignVerifyTest();

        cryptoApiTester.RunPgpEccFileStreamingTest();

        // TODO: Investigate local gpg-agent socket creation failure in the two GnuPG import tests
        // below. GnuPG reports the public key as imported, then exits with rc=2 because the agent
        // cannot bind its socket under AppData\Local\gnupg ("No such file or directory").
        cryptoApiTester.RunPgpGnuPgInteropTest();

        cryptoApiTester.RunPgpKeyExpirationTest();

        cryptoApiTester.RunPgpGnuPgRevocationInteropTest();

        cryptoApiTester.RunPgpMultiRecipientEncryptDecryptTest();

        cryptoApiTester.RunPgpMixedRecipientEncryptDecryptTest();

        cryptoApiTester.RunPgpMultiRecipientFileEncryptDecryptTest();

        cryptoApiTester.RunPgpGnuPgMultiRecipientInteropTest();

        cryptoApiTester.RunPgpGnuPgMixedAlgorithmRecipientInteropTest();

        cryptoApiTester.RunPgpEd25519KeyGenerationTest();

        cryptoApiTester.RunPgpEd25519EncryptDecryptTest();

        cryptoApiTester.RunPgpEd25519SignVerifyTest();

        cryptoApiTester.RunPgpEd25519ClearSignTest();

        cryptoApiTester.RunPgpGnuPgEd25519InteropTest();

        cryptoApiTester.RunPgpEd25519KeyExpirationTest();

        cryptoApiTester.RunPgpGnuPgEd25519RevocationInteropTest();

        cryptoApiTester.RunPgpEncryptFileCompressedZipTest();

        cryptoApiTester.RunPgpEncryptFileCompressedZlibTest();

        cryptoApiTester.RunPgpEncryptFileCompressedEmptyFileTest();

        cryptoApiTester.RunPgpEncryptFileCompressedLargeFileTest();

        cryptoApiTester.RunPgpEncryptFileCompressedCancellationTest();

        cryptoApiTester.RunPgpEncryptFileCompressedCorruptionTest();

        cryptoApiTester.RunPgpGnuPgBzip2InteropTest();

        cryptoApiTester.RunPgpGnuPgBzip2DecryptBufferInteropTest();

        cryptoApiTester.RunPgpGnuPgPartialBodyLengthInteropTest();

        cryptoApiTester.RunPgpInspectionEncryptedMessageTest();

        cryptoApiTester.RunPgpInspectionMultiRecipientTest();

        cryptoApiTester.RunPgpInspectionSignatureTest();

        cryptoApiTester.RunPgpGnuPgInspectionInteropTest();
#endif

#if 0
        cryptoApiTester.RunPgpWrapperAvailabilityTest();

        cryptoApiTester.RunPgpWrapperKeyGenerationTest();

        cryptoApiTester.RunPgpWrapperEncryptDecryptTest();  // FAILED, PASSED

        cryptoApiTester.RunPgpWrapperSignVerifyTest();

        cryptoApiTester.RunPgpWrapperClearSignTest();

        cryptoApiTester.RunPgpWrapperAliceBobTest();

        cryptoApiTester.RunPgpWrapperFileEncryptDecryptTest();

        cryptoApiTester.RunPgpWrapperFileSignVerifyTest();

        cryptoApiTester.RunPgpWrapperKeyExpirationTest();

        cryptoApiTester.RunPgpWrapperKeyRevocationTest();

        cryptoApiTester.RunPgpWrapperMultiRecipientEncryptTest();

        cryptoApiTester.RunPgpWrapperEccKeyGenerationTest();

        cryptoApiTester.RunPgpWrapperSymmetricEncryptDecryptTest();

        cryptoApiTester.RunPgpWrapperKeyringListDeleteTest();

        cryptoApiTester.RunPgpWrapperCompressionAlgorithmTest();

        cryptoApiTester.RunPgpWrapperInspectionEncryptedMessageTest();

        cryptoApiTester.RunPgpWrapperInspectionMultiRecipientTest();

        cryptoApiTester.RunPgpWrapperInspectionSymmetricTest();

        cryptoApiTester.RunPgpWrapperInspectionSignatureTest();
#endif

#if 1
        // Closes 3 previously-zero-coverage interface methods flagged by the 2026-09-22 runner
        // parity audit (see memory project_runner_parity_audit_findings.md): IPgpEngine::
        // GetPeerKeyId, IPgpEngineWrapper::GetPeerKeyId, and both IPgpEngineWrapper::
        // EncryptStringArmoredMultiRecipient overloads. Kept in its own always-on block
        // (independent of the surrounding #if 0 PGP-wrapper block above) so these run regardless
        // of that block's own on/off state. Same tests AppBuilder/Main.cpp now also calls.
        cryptoApiTester.RunPgpGetPeerKeyIdTest();

        cryptoApiTester.RunPgpWrapperGetPeerKeyIdTest();

        cryptoApiTester.RunPgpWrapperMultiRecipientEncryptStringArmoredTest();
#endif
    }
    catch (...)
    {

    }

    return 0;
}

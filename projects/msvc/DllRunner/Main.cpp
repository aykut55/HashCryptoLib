#include <iostream>
#include <string>
#include <vector>
#include <cstring>

// ChaiScriptEngine.h pulls in <chaiscript/chaiscript.hpp>, which transitively includes
// <Windows.h> (for ChaiScript's own threading support) -- chaiscript_windows.hpp calls the real
// Win32 LoadLibrary function internally, relying on the UNICODE-charset macro that redirects the
// bare token "LoadLibrary" to LoadLibraryA/LoadLibraryW. DllLoader/CryptoApiDllLoader.h's own
// "#undef LoadLibrary" (below) exists so CCryptoApiDllLoader's own method of that same name keeps
// its exact compiled name instead of silently becoming LoadLibraryA/W -- but applied in this
// translation unit BEFORE ChaiScriptEngine.h, it would just as silently break ChaiScript's own,
// unrelated use of the real Win32 function (observed directly: C3861 "'LoadLibrary': identifier
// not found" from chaiscript_windows.hpp). Including ChaiScriptEngine.h first, so its own
// Windows.h pull and every LoadLibrary token inside it are fully parsed before that undef runs,
// avoids the collision; the defensive NO_ERROR/EncryptFile/DecryptFile undefs right after it are
// the same precedent every other file in this SDK uses around a Windows.h-pulling scripting
// library's own include (see ChaiScriptEngine.cpp's own top-of-file comment for the full
// reasoning), applied here too since chaiscript.hpp's own Windows.h pull happens before
// CryptoApiDllLoader.h's (narrower, LEAN_AND_MEAN) one below.
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

#include "DllLoader/CryptoApiDllLoader.h"

#include "Scripts/ScriptCryptoApiDll.h"
#include "Scripts/ScriptPgpEngineDll.h"
#include "Scripts/ScriptPgpEngineWrapperDll.h"
#include "Scripts/LuaScript/LuaScriptEngineSol.h"
#include "Scripts/LuaScript/LuaScriptEngineLuaBridge.h"
#include "Scripts/LuaScript/LuaScriptEngineLuaBridgeLegacy.h"
#include "Scripts/PythonScript/PythonScriptEngine.h"

int main()
{
    std::string dllFileName = "CryptoApi.dll";

    CryptoApiNS::CCryptoApiDllLoader* pCryptoApiDllLoader = nullptr;

	CryptoApiNS::ICryptoApi* pCryptoApi = nullptr;

    try
    {
        std::cout << "Hello World!\n";
        std::cout << std::endl;

        pCryptoApiDllLoader = new CryptoApiNS::CCryptoApiDllLoader();

        if (pCryptoApiDllLoader)
        {
            pCryptoApiDllLoader->SetFileName(dllFileName);

            if (pCryptoApiDllLoader->LoadLibrary())
            {
                std::cout << "CryptoApi.dll loaded successfully." << std::endl;
            }
            else
            {
                std::cout << "Failed to load CryptoApi.dll." << std::endl;
            }

            if (pCryptoApiDllLoader->IsLoaded())
            {
                pCryptoApi = pCryptoApiDllLoader->GetCryptoApiObject();

                if (pCryptoApi)
                {
                    std::cout << std::endl;

                    std::cout << "CryptoAPI version: " << pCryptoApi->GetVersion() << std::endl;

                    std::cout << std::endl;

                    // testleri kostur..
                    CryptoApiNS::ICryptoApiTester* pCryptoApiTester = pCryptoApiDllLoader->GetCryptoApiTesterObject();

                    if (pCryptoApiTester)
                    {
                        pCryptoApiTester->RunEncryptDecryptFileTest();

                        pCryptoApiTester->RunEncryptDecryptStringTest();

                        pCryptoApiTester->RunEncryptDecryptBufferTest();

                        pCryptoApiTester->RunEncryptDecryptBytesTest();

                        pCryptoApiDllLoader->DestroyCryptoApiTesterObject(pCryptoApiTester);
                    }
                }

                pCryptoApiDllLoader->DestroyCryptoApiObject(pCryptoApi);
            }

            if (pCryptoApiDllLoader->IsLoaded())
            {
                // IPgpEngine round trip through the DLL boundary: GenerateKeyPair, export this
                // instance's own public key, re-import it as its own "peer" (a self-contained
                // Alice-to-Alice round trip, same pattern CCryptoApiTester's own PGP tests use),
                // encrypt, decrypt, and compare -- proves the DLL's CreatePgpEngine()/IPgpEngine
                // virtual dispatch works end to end, not just that it links.
                CryptoApiNS::IPgpEngine* pPgpEngine = pCryptoApiDllLoader->GetPgpEngineObject();

                if (pPgpEngine)
                {
                    std::cout << std::endl;

                    const char* userId = "DllRunner Test <dllrunner@example.com>";
                    const char* password = "DllRunnerTestPassword123";
                    const char* plaintext = "Hello from DllRunner via IPgpEngine!";

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

                        std::cout << "IPgpEngine EncryptStringArmored/DecryptStringArmored round trip: "
                                  << (decrypted == plaintext ? "PASSED" : "FAILED") << std::endl;
                    }
                    else
                    {
                        std::cout << "IPgpEngine::GenerateKeyPair failed, rc=" << rc << std::endl;
                    }

                    pCryptoApiDllLoader->DestroyPgpEngineObject(pPgpEngine);
                }

                // IPgpEngineWrapper round trip through the DLL boundary -- delegates to a real
                // gpg.exe child process instead of CPgpEngine's own RFC 4880 implementation.
                // Unlike IPgpEngine above, this cannot use a self-import (Alice-to-Alice) round
                // trip: gpg's own "--import" reports a key that is already present in the keyring
                // (as it would be here, right after this same instance's own GenerateKeyPair) as
                // "unchanged" rather than "IMPORTED", which importPeerPublicKeyCommon (see
                // Pgp/PgpEngineWrapper.cpp) treats as INVALID_DATA, not success -- verified
                // directly against this machine's gpg.exe while wiring this test up. Uses two
                // separate engine instances (each its own isolated --homedir) instead, matching
                // CCryptoApiTester::RunPgpWrapperEncryptDecryptTest's own Alice/Bob pattern.
                // Skipped gracefully if no local GnuPG install is found (IsGnuPgAvailable), same
                // convention every other GnuPG-backed test in this repo follows.
                CryptoApiNS::IPgpEngineWrapper* pAlice = pCryptoApiDllLoader->GetPgpEngineWrapperObject();
                CryptoApiNS::IPgpEngineWrapper* pBob = pCryptoApiDllLoader->GetPgpEngineWrapperObject();

                if (pAlice && pBob)
                {
                    std::cout << std::endl;

                    if (pAlice->IsGnuPgAvailable())
                    {
                        const char* aliceUserId = "DllRunner Alice <dllrunner-alice@example.com>";
                        const char* alicePassword = "DllRunnerAlicePassword123";
                        const char* bobUserId = "DllRunner Bob <dllrunner-bob@example.com>";
                        const char* bobPassword = "DllRunnerBobPassword123";
                        const char* plaintext = "Hello Bob from DllRunner via IPgpEngineWrapper!";

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

                            // Alice imports Bob's public key (to encrypt TO Bob); Bob imports
                            // Alice's public key (needed by DecryptStringArmored's own peer
                            // precondition, mirroring CPgpEngine's own contract).
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

                            std::cout << "IPgpEngineWrapper Alice->Bob EncryptStringArmored/DecryptStringArmored round trip: "
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
                }

                if (pAlice)
                {
                    pCryptoApiDllLoader->DestroyPgpEngineWrapperObject(pAlice);
                }
                if (pBob)
                {
                    pCryptoApiDllLoader->DestroyPgpEngineWrapperObject(pBob);
                }
            }

            // Scripting via the DLL: fresh ICryptoApi*/IPgpEngine*/IPgpEngineWrapper* obtained
            // from the SAME loaded CryptoAPI.dll, wrapped in the lightweight CScriptCryptoApiDll/
            // CScriptPgpEngineDll/CScriptPgpEngineWrapperDll facades (see ScriptCryptoApiDll.h's
            // own header comment for why these are separate from CScriptCryptoApi/CScriptPgpEngine/
            // CScriptPgpEngineWrapper), then injected into each of the 5 script engines as the
            // globals "cryptoApi"/"pgpEngine"/"pgpEngineWrapper" via SetDllCryptoApi/SetDllPgpEngine/
            // SetDllPgpEngineWrapper. Every engine runs the SAME embedded script logic (only the
            // syntax differs per language): a hash length check, a PGP self-import encrypt/decrypt
            // round trip (see IPgpEngine's own DLL round trip above for why self-import is valid for
            // CPgpEngine but NOT for CPgpEngineWrapper's real-gpg backend -- so the wrapper portion
            // only exercises GenerateKeyPair/ExportPublicKeyArmored, not a full encrypt/decrypt,
            // matching that same constraint), each check length-only (no cross-language byte-vector
            // equality helper is registered for the *Dll facades, unlike the local ones' ToBytes/
            // ToStringFromBytes) rather than exact-string comparison.
            CryptoApiNS::ICryptoApi* pScriptCryptoApi = pCryptoApiDllLoader->GetCryptoApiObject();
            CryptoApiNS::IPgpEngine* pScriptPgpEngine = pCryptoApiDllLoader->GetPgpEngineObject();
            CryptoApiNS::IPgpEngineWrapper* pScriptPgpEngineWrapper = pCryptoApiDllLoader->GetPgpEngineWrapperObject();

            if (pScriptCryptoApi && pScriptPgpEngine && pScriptPgpEngineWrapper)
            {
                std::cout << std::endl;

                CryptoApiNS::CScriptCryptoApiDll scriptCryptoApi(pScriptCryptoApi);
                CryptoApiNS::CScriptPgpEngineDll scriptPgpEngine(pScriptPgpEngine);
                CryptoApiNS::CScriptPgpEngineWrapperDll scriptPgpEngineWrapper(pScriptPgpEngineWrapper);

                const char* luaScript =
                    "local hashResult = cryptoApi:ComputeHashString(\"hello\")\n"
                    "local hashOk = (#hashResult == cryptoApi:GetHashSize())\n"
                    "\n"
                    "pgpEngine:GenerateKeyPair(\"DLL Script Test <script@example.com>\", \"ScriptTestPassword123\")\n"
                    "local pub = pgpEngine:ExportPublicKeyArmored()\n"
                    "pgpEngine:ImportPeerPublicKey(pub)\n"
                    "local plaintext = \"Hello via script and DLL!\"\n"
                    "local cipher = pgpEngine:EncryptStringArmored(plaintext)\n"
                    "local plainBytes = pgpEngine:DecryptStringArmored(\"ScriptTestPassword123\", cipher)\n"
                    "local pgpOk = (#plainBytes == #plaintext)\n"
                    "\n"
                    "local wrapperOk = true\n"
                    "if pgpEngineWrapper:IsGnuPgAvailable() then\n"
                    "    pgpEngineWrapper:GenerateKeyPair(\"DLL Wrapper Test <wrapper@example.com>\", \"WrapperTestPassword123\")\n"
                    "    local wpub = pgpEngineWrapper:ExportPublicKeyArmored()\n"
                    "    wrapperOk = (#wpub > 0)\n"
                    "end\n"
                    "\n"
                    "ok = hashOk and pgpOk and wrapperOk\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaEngine.SetDllPgpEngine(&scriptPgpEngine);
                    luaEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    luaEngine.RunString(luaScript);
                    std::cout << "DLL-hosted scripting (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting (sol2): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeEngine.SetDllPgpEngine(&scriptPgpEngine);
                    luaBridgeEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    luaBridgeEngine.RunString(luaScript);
                    std::cout << "DLL-hosted scripting (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeLegacyEngine.SetDllPgpEngine(&scriptPgpEngine);
                    luaBridgeLegacyEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    luaBridgeLegacyEngine.RunString(luaScript);
                    std::cout << "DLL-hosted scripting (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* chaiScript =
                    "var hashResult = cryptoApi.ComputeHashString(\"hello\");\n"
                    "var hashOk = (hashResult.size() == cryptoApi.GetHashSize());\n"
                    "\n"
                    "pgpEngine.GenerateKeyPair(\"DLL Script Test <script@example.com>\", \"ScriptTestPassword123\");\n"
                    "var pub = pgpEngine.ExportPublicKeyArmored();\n"
                    "pgpEngine.ImportPeerPublicKey(pub);\n"
                    "var plaintext = \"Hello via script and DLL!\";\n"
                    "var cipher = pgpEngine.EncryptStringArmored(plaintext);\n"
                    "var plainBytes = pgpEngine.DecryptStringArmored(\"ScriptTestPassword123\", cipher);\n"
                    "var pgpOk = (plainBytes.size() == plaintext.size());\n"
                    "\n"
                    "var wrapperOk = true;\n"
                    "if (pgpEngineWrapper.IsGnuPgAvailable()) {\n"
                    "    pgpEngineWrapper.GenerateKeyPair(\"DLL Wrapper Test <wrapper@example.com>\", \"WrapperTestPassword123\");\n"
                    "    var wpub = pgpEngineWrapper.ExportPublicKeyArmored();\n"
                    "    wrapperOk = (wpub.size() > 0);\n"
                    "}\n"
                    "\n"
                    "global ok = (hashOk && pgpOk && wrapperOk);\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllCryptoApi(&scriptCryptoApi);
                    chaiEngine.SetDllPgpEngine(&scriptPgpEngine);
                    chaiEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    chaiEngine.RunString(chaiScript);
                    std::cout << "DLL-hosted scripting (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* pythonScript =
                    "hashResult = cryptoApi.ComputeHashString(\"hello\")\n"
                    "hashOk = (len(hashResult) == cryptoApi.GetHashSize())\n"
                    "\n"
                    "pgpEngine.GenerateKeyPair(\"DLL Script Test <script@example.com>\", \"ScriptTestPassword123\")\n"
                    "pub = pgpEngine.ExportPublicKeyArmored()\n"
                    "pgpEngine.ImportPeerPublicKey(pub)\n"
                    "plaintext = \"Hello via script and DLL!\"\n"
                    "cipher = pgpEngine.EncryptStringArmored(plaintext)\n"
                    "plainBytes = pgpEngine.DecryptStringArmored(\"ScriptTestPassword123\", cipher)\n"
                    "pgpOk = (len(plainBytes) == len(plaintext))\n"
                    "\n"
                    "wrapperOk = True\n"
                    "if pgpEngineWrapper.IsGnuPgAvailable():\n"
                    "    pgpEngineWrapper.GenerateKeyPair(\"DLL Wrapper Test <wrapper@example.com>\", \"WrapperTestPassword123\")\n"
                    "    wpub = pgpEngineWrapper.ExportPublicKeyArmored()\n"
                    "    wrapperOk = (len(wpub) > 0)\n"
                    "\n"
                    "ok = hashOk and pgpOk and wrapperOk\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllCryptoApi(&scriptCryptoApi);
                    pythonEngine.SetDllPgpEngine(&scriptPgpEngine);
                    pythonEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    pythonEngine.RunString(pythonScript);
                    std::cout << "DLL-hosted scripting (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting (Python): FAILED exception " << ex.what() << std::endl;
                }
            }

            if (pScriptCryptoApi)
            {
                pCryptoApiDllLoader->DestroyCryptoApiObject(pScriptCryptoApi);
            }
            if (pScriptPgpEngine)
            {
                pCryptoApiDllLoader->DestroyPgpEngineObject(pScriptPgpEngine);
            }
            if (pScriptPgpEngineWrapper)
            {
                pCryptoApiDllLoader->DestroyPgpEngineWrapperObject(pScriptPgpEngineWrapper);
            }
        }

        delete pCryptoApiDllLoader;
    }
    catch (...)
    {

    }

    return 0;
}

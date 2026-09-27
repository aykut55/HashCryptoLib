#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <fstream>

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

#include <shellapi.h>

#include "DllLoader/CryptoApiDllLoader.h"
#include "Cli/CommandLineParser.h"
#include "Utils/Utils.h"

#include "Scripts/ScriptCryptoApiDll.h"
#include "Scripts/ScriptPgpEngineDll.h"
#include "Scripts/ScriptPgpEngineWrapperDll.h"
#include "Scripts/ScriptCertificateManagerDll.h"
#include "Scripts/ScriptCmsServiceDll.h"
#include "Scripts/ScriptTimestampServiceDll.h"
#include "Scripts/LuaScript/LuaScriptEngineSol.h"
#include "Scripts/LuaScript/LuaScriptEngineLuaBridge.h"
#include "Scripts/LuaScript/LuaScriptEngineLuaBridgeLegacy.h"
#include "Scripts/PythonScript/PythonScriptEngine.h"

// Real Unicode command-line args (excludes argv[0]), converted to UTF-8 -- same reasoning as
// AppBuilder/Main.cpp's own identical helper (see the AppRunner CLI harness plan).
std::vector<std::string> getUtf8CommandLineArgs()
{
    std::vector<std::string> result;
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argvW == nullptr)
    {
        return result;
    }

    for (int i = 1; i < argc; ++i)
    {
        const int utf8Size = WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, nullptr, 0, nullptr, nullptr);
        if (utf8Size <= 0)
        {
            continue;
        }
        std::vector<char> buffer(static_cast<std::size_t>(utf8Size));
        WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, buffer.data(), utf8Size, nullptr, nullptr);
        result.emplace_back(buffer.data());
    }

    LocalFree(argvW);
    return result;
}
// -----------------------------------------------------------------------------

// Phase 2 of the AppRunner CLI harness plan: DllRunner gets the IDENTICAL action set AppBuilder's
// Main.cpp implements (see its own copy of these 4 functions for the calling-convention precedent),
// but dispatching through the DLL-hosted ICryptoApi*/IPgpEngine* obtained via CCryptoApiDllLoader
// instead of the in-process CCryptoApi/CPgpEngine classes -- proves the same CLI surface works
// identically across both consumption modes.
int runCliActionHash(const CryptoApiNS::CCommandLineParser& parser, CryptoApiNS::ICryptoApi* pCryptoApi)
{
    const std::string input = parser.GetString("input", "");

    unsigned char digest[64];
    int digestSize = 0;
    const int status = pCryptoApi->ComputeHashString( input.c_str(), static_cast<int>(input.size()),
                                                      sizeof(digest), digest, &digestSize, nullptr, nullptr);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ComputeHashString failed, status=" << status << std::endl;
        return 1;
    }

    char hexOut[160];
    int hexOutSize = 0;
    CryptoApiNS::CUtils::HexEncode(digest, digestSize, false, sizeof(hexOut), hexOut, &hexOutSize);
    std::cout << std::string(hexOut, static_cast<std::size_t>(hexOutSize)) << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionEncryptString(const CryptoApiNS::CCommandLineParser& parser, CryptoApiNS::ICryptoApi* pCryptoApi)
{
    const std::string password = parser.GetString("password", "");
    const std::string input = parser.GetString("input", "");

    unsigned char cipherBuffer[8192];
    int cipherSize = 0;
    const int status = pCryptoApi->EncryptString( password.c_str(), static_cast<int>(password.size()),
                                                  input.c_str(), static_cast<int>(input.size()),
                                                  sizeof(cipherBuffer), cipherBuffer, &cipherSize, nullptr, nullptr);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "EncryptString failed, status=" << status << std::endl;
        return 1;
    }

    char base64Out[16384];
    int base64OutSize = 0;
    CryptoApiNS::CUtils::Base64Encode(cipherBuffer, cipherSize, sizeof(base64Out), base64Out, &base64OutSize);
    std::cout << std::string(base64Out, static_cast<std::size_t>(base64OutSize)) << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionDecryptString(const CryptoApiNS::CCommandLineParser& parser, CryptoApiNS::ICryptoApi* pCryptoApi)
{
    const std::string password = parser.GetString("password", "");
    const std::string input = parser.GetString("input", "");

    unsigned char cipherBuffer[8192];
    int cipherSize = 0;
    if (CryptoApiNS::CUtils::Base64Decode( input.c_str(), static_cast<int>(input.size()),
                                          sizeof(cipherBuffer), cipherBuffer, &cipherSize) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "Base64Decode of -input failed" << std::endl;
        return 1;
    }

    char plainBuffer[8192];
    int plainSize = 0;
    const int status = pCryptoApi->DecryptString( password.c_str(), static_cast<int>(password.size()),
                                                  cipherBuffer, cipherSize,
                                                  sizeof(plainBuffer), plainBuffer, &plainSize, nullptr, nullptr);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "DecryptString failed, status=" << status << std::endl;
        return 1;
    }

    std::cout << std::string(plainBuffer, static_cast<std::size_t>(plainSize)) << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionPgpRoundtrip(const CryptoApiNS::CCommandLineParser& parser, CryptoApiNS::IPgpEngine* pPgpEngine)
{
    const std::string userId = parser.GetString("userid", "CLI Test <cli-test@example.com>");
    const std::string password = parser.GetString("password", "");
    const std::string message = parser.GetString("message", "");

    int status = pPgpEngine->GenerateKeyPair( userId.c_str(), static_cast<int>(userId.size()),
                                              password.c_str(), static_cast<int>(password.size()));
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "GenerateKeyPair failed, status=" << status << std::endl;
        return 1;
    }

    char pubKeyArmored[16384];
    int pubKeySize = 0;
    status = pPgpEngine->ExportPublicKeyArmored(sizeof(pubKeyArmored), pubKeyArmored, &pubKeySize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ExportPublicKeyArmored failed, status=" << status << std::endl;
        return 1;
    }

    status = pPgpEngine->ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(pubKeyArmored), pubKeySize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ImportPeerPublicKey failed, status=" << status << std::endl;
        return 1;
    }

    char encryptedArmored[16384];
    int encryptedSize = 0;
    status = pPgpEngine->EncryptStringArmored( message.c_str(), static_cast<int>(message.size()),
                                               sizeof(encryptedArmored), encryptedArmored, &encryptedSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "EncryptStringArmored failed, status=" << status << std::endl;
        return 1;
    }

    unsigned char decryptedBuffer[16384];
    int decryptedSize = 0;
    status = pPgpEngine->DecryptStringArmored( password.c_str(), static_cast<int>(password.size()),
                                              encryptedArmored, encryptedSize,
                                              sizeof(decryptedBuffer), decryptedBuffer, &decryptedSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "DecryptStringArmored failed, status=" << status << std::endl;
        return 1;
    }

    const std::string decryptedText(reinterpret_cast<const char*>(decryptedBuffer), static_cast<std::size_t>(decryptedSize));
    std::cout << decryptedText << std::endl;
    return (decryptedText == message) ? 0 : 5;
}
// -----------------------------------------------------------------------------

// Defined at the bottom of this file (it's the exact sequence main() always ran unconditionally
// before the CLI existed -- DLL load, native ICryptoApiTester suite, all 5 script engines' own
// demo/test suites). Forward-declared here so runCliMode's "run-tests" action can reach it without
// reordering that huge block.
int runAllTests();
// -----------------------------------------------------------------------------

// Loads CryptoAPI.dll just long enough to dispatch one CLI action, then unloads -- entirely
// separate from the huge script-engine/test-suite flow below, gated purely on argc (see main()).
int runCliMode(const CryptoApiNS::CCommandLineParser& parser)
{
    const std::string action = parser.GetString("action", "");
    if (action == "run-tests")
    {
        return runAllTests();
    }

    CryptoApiNS::CCryptoApiDllLoader dllLoader;
    dllLoader.SetFileName("CryptoApi.dll");
    if (!dllLoader.LoadLibrary() || !dllLoader.IsLoaded())
    {
        std::cerr << "Failed to load CryptoApi.dll" << std::endl;
        return 3;
    }

    int result = 2;

    if (action == "version")
    {
        CryptoApiNS::ICryptoApi* pCryptoApi = dllLoader.GetCryptoApiObject();
        if (pCryptoApi != nullptr)
        {
            std::cout << pCryptoApi->GetVersion() << std::endl;
            dllLoader.DestroyCryptoApiObject(pCryptoApi);
            result = 0;
        }
    }
    else if (action == "hash" || action == "encrypt-string" || action == "decrypt-string")
    {
        CryptoApiNS::ICryptoApi* pCryptoApi = dllLoader.GetCryptoApiObject();
        if (pCryptoApi != nullptr)
        {
            if (action == "hash") { result = runCliActionHash(parser, pCryptoApi); }
            else if (action == "encrypt-string") { result = runCliActionEncryptString(parser, pCryptoApi); }
            else { result = runCliActionDecryptString(parser, pCryptoApi); }
            dllLoader.DestroyCryptoApiObject(pCryptoApi);
        }
    }
    else if (action == "pgp-roundtrip")
    {
        CryptoApiNS::IPgpEngine* pPgpEngine = dllLoader.GetPgpEngineObject();
        if (pPgpEngine != nullptr)
        {
            result = runCliActionPgpRoundtrip(parser, pPgpEngine);
            dllLoader.DestroyPgpEngineObject(pPgpEngine);
        }
    }
    else
    {
        std::cerr << "Unknown or missing -action. Supported actions: version, hash, encrypt-string, "
                     "decrypt-string, pgp-roundtrip, run-tests" << std::endl;
    }

    dllLoader.UnloadLibrary();
    return result;
}
// -----------------------------------------------------------------------------

int runAllTests()
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
                        pCryptoApiTester->Run();

                        pCryptoApiTester->RunEncryptDecryptFileTest();

                        pCryptoApiTester->RunEncryptDecryptStringTest();

                        pCryptoApiTester->RunEncryptDecryptBufferTest();

                        pCryptoApiTester->RunEncryptDecryptBytesTest();

                        // Native ICryptoApiTester test parity with AppBuilder/LibRunner's own Main.cpp
                        // (ranked-list item 4 -- see prompt2.md/[[project_runner_parity_audit_findings]]):
                        // DllRunner previously only ever called the 4 basic EncryptDecrypt*Test methods
                        // above through the DLL boundary, even though ICryptoApiTester already declares
                        // every CCryptoApiTester test method as pure virtual (so CCryptoApiTester,
                        // constructed inside CryptoAPI.dll via CreateCryptoApiTester(), already implements
                        // all of them -- no new interface/header/cpp plumbing needed, purely additive
                        // calls here). Same PGP block, GetPeerKeyId block, and Certificate/CMS/Timestamp
                        // block LibRunner/Main.cpp enables (#if 1) as of its own native test parity pass.
                        pCryptoApiTester->RunPgpKeyGenerationTest();

                        pCryptoApiTester->RunPgpEncryptDecryptTest();

                        pCryptoApiTester->RunPgpSignVerifyTest();

                        pCryptoApiTester->RunPgpClearSignTest();

                        pCryptoApiTester->RunPgpArmorTest();

                        pCryptoApiTester->RunPgpAliceBobTest();

                        pCryptoApiTester->RunPgpFileEncryptDecryptTest();

                        pCryptoApiTester->RunPgpFileSignVerifyTest();

                        pCryptoApiTester->RunPgpEccFileStreamingTest();

                        pCryptoApiTester->RunPgpGnuPgInteropTest();

                        pCryptoApiTester->RunPgpKeyExpirationTest();

                        pCryptoApiTester->RunPgpGnuPgRevocationInteropTest();

                        pCryptoApiTester->RunPgpMultiRecipientEncryptDecryptTest();

                        pCryptoApiTester->RunPgpMixedRecipientEncryptDecryptTest();

                        pCryptoApiTester->RunPgpMultiRecipientFileEncryptDecryptTest();

                        pCryptoApiTester->RunPgpGnuPgMultiRecipientInteropTest();

                        pCryptoApiTester->RunPgpGnuPgMixedAlgorithmRecipientInteropTest();

                        pCryptoApiTester->RunPgpEd25519KeyGenerationTest();

                        pCryptoApiTester->RunPgpEd25519EncryptDecryptTest();

                        pCryptoApiTester->RunPgpEd25519SignVerifyTest();

                        pCryptoApiTester->RunPgpEd25519ClearSignTest();

                        pCryptoApiTester->RunPgpGnuPgEd25519InteropTest();

                        pCryptoApiTester->RunPgpEd25519KeyExpirationTest();

                        pCryptoApiTester->RunPgpGnuPgEd25519RevocationInteropTest();

                        pCryptoApiTester->RunPgpEncryptFileCompressedZipTest();

                        pCryptoApiTester->RunPgpEncryptFileCompressedZlibTest();

                        pCryptoApiTester->RunPgpEncryptFileCompressedEmptyFileTest();

                        pCryptoApiTester->RunPgpEncryptFileCompressedLargeFileTest();

                        pCryptoApiTester->RunPgpEncryptFileCompressedCancellationTest();

                        pCryptoApiTester->RunPgpEncryptFileCompressedCorruptionTest();

                        pCryptoApiTester->RunPgpGnuPgBzip2InteropTest();

                        pCryptoApiTester->RunPgpGnuPgBzip2DecryptBufferInteropTest();

                        pCryptoApiTester->RunPgpGnuPgPartialBodyLengthInteropTest();

                        pCryptoApiTester->RunPgpInspectionEncryptedMessageTest();

                        pCryptoApiTester->RunPgpInspectionMultiRecipientTest();

                        pCryptoApiTester->RunPgpInspectionSignatureTest();

                        pCryptoApiTester->RunPgpGnuPgInspectionInteropTest();

                        pCryptoApiTester->RunPgpGetPeerKeyIdTest();

                        pCryptoApiTester->RunPgpWrapperGetPeerKeyIdTest();

                        pCryptoApiTester->RunPgpWrapperMultiRecipientEncryptStringArmoredTest();

                        pCryptoApiTester->RunCertificateSelfSignedTest();

                        pCryptoApiTester->RunCertificateDerPemRoundtripTest();

                        pCryptoApiTester->RunCertificatePfxImportExportTest();

                        pCryptoApiTester->RunCertificateCsrGenerationTest();

                        pCryptoApiTester->RunCertificateCsrDerPemRoundtripTest();

                        pCryptoApiTester->RunCertificateIssueFromRequestTest();

                        pCryptoApiTester->RunCertificateChainValidTest();

                        pCryptoApiTester->RunCertificateChainUntrustedRootTest();

                        pCryptoApiTester->RunCertificateChainExpiredTest();

                        pCryptoApiTester->RunCertificateChainRevokedTest();

                        pCryptoApiTester->RunCertificateCrlCheckGoodTest();

                        pCryptoApiTester->RunCertificateCrlCheckRevokedTest();

                        pCryptoApiTester->RunCertificateCrlCheckStaleTest();

                        pCryptoApiTester->RunCertificateCrlCheckWrongIssuerRejectionTest();

                        pCryptoApiTester->RunCertificateChainCrypt32CdpFetchRevokedTest();

                        pCryptoApiTester->RunCertificateStoreMemoryFindTest();

                        pCryptoApiTester->RunCertificateStoreFindByFilterTest();

                        pCryptoApiTester->RunCmsSignVerifyDetachedTest();

                        pCryptoApiTester->RunCmsTamperedDataRejectionTest();

                        pCryptoApiTester->RunCmsUntrustedSignerRejectionTest();

                        pCryptoApiTester->RunCmsSigningCertificateV2AttributeTest();

                        pCryptoApiTester->RunCmsVerifyDetachedSigningCertMismatchTest();

                        pCryptoApiTester->RunTimestampRequestResponseRoundtripTest();

                        pCryptoApiTester->RunTimestampVerifyTest();

                        pCryptoApiTester->RunTimestampTamperedDigestRejectionTest();

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

            // Second, genuinely independent ICryptoApi instance ("bob") -- GetCryptoApiObject calls
            // CreateCryptoApi() inside the loaded DLL again, which allocates a fresh CCryptoApi, not
            // a second handle to the same one. Exists solely for the KeyAgreement demo below, which
            // needs two separate key pairs to do a real two-party exchange (unlike every other demo
            // in this block, which only ever needs the one shared pScriptCryptoApi/scriptCryptoApi).
            CryptoApiNS::ICryptoApi* pScriptCryptoApiBob = pCryptoApiDllLoader->GetCryptoApiObject();

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

                // DLL-hosted progress-callback round trip: proves a script-supplied callback still
                // gets called once per chunk (C++-calls-INTO-script direction, see
                // ScriptProgressCallback.h's own comment) when EncryptFileWithProgress runs against
                // an ICryptoApi* obtained purely from CryptoAPI.dll at runtime
                // (CCryptoApiDllLoader::GetCryptoApiObject()), not linked against at compile time --
                // same mechanism AppBuilder's own RunXxxScriptProgressCallbackTest already proves for
                // the statically-linked CScriptCryptoApi. Reuses the same scriptCryptoApi/cryptoApi
                // global the hash/PGP demo above just exercised. File size (5120 bytes) and chunk
                // count assertion (>= 3 calls) match ScriptEngineTester.cpp's own
                // WriteProgressCallbackTestFile/kProgressCallbackTestFileSize convention.
                const char* progressInputPath = "dllrunner_progress_test_in.bin";
                const char* progressEncPath = "dllrunner_progress_test_enc.bin";

                {
                    std::vector<unsigned char> progressTestData(5120, 'A');
                    std::ofstream progressInputFile(progressInputPath, std::ios::binary);
                    progressInputFile.write(reinterpret_cast<const char*>(progressTestData.data()), static_cast<std::streamsize>(progressTestData.size()));
                }

                const char* progressLuaScript =
                    "callCount = 0\n"
                    "lastCurrentByte = 0\n"
                    "local function onProgress(currentByte, totalByte, percentage)\n"
                    "    callCount = callCount + 1\n"
                    "    lastCurrentByte = currentByte\n"
                    "    return true\n"
                    "end\n"
                    "cryptoApi:EncryptFileWithProgress(\"dllprogresstest\", \"dllrunner_progress_test_in.bin\", \"dllrunner_progress_test_enc.bin\", onProgress)\n"
                    "ok = (callCount >= 3) and (lastCurrentByte == 5120)\n";

                // sol2 only: a second level of C++-calls-INTO-script nesting on top of the per-chunk
                // onProgress callback -- inside onProgress itself, the script calls the bound C++
                // function OnProgress (now registered unconditionally in LuaScriptEngineSol.cpp's
                // registerBindings, see that binding's own comment), which immediately calls back
                // into a SECOND script-defined function (innerCallback), then unwinds all the way
                // back to the C++ file loop. Same demonstration LibRunner's own static-link progress
                // callback block already proves, now shown working against a DLL-hosted
                // CScriptCryptoApiDll too -- closes the parity gap this block used to have.
                const char* progressLuaScriptWithInnerCallback =
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
                    "cryptoApi:EncryptFileWithProgress(\"dllprogresstest\", \"dllrunner_progress_test_in.bin\", \"dllrunner_progress_test_enc.bin\", onProgress)\n"
                    "ok = (callCount >= 3) and (lastCurrentByte == 5120) and (innerCallCount == callCount)\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaEngine.RunString(progressLuaScriptWithInnerCallback);
                    std::cout << "DLL-hosted progress callback (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED")
                              << " callCount=" << luaEngine.GetGlobalInt("callCount") << " innerCallCount=" << luaEngine.GetGlobalInt("innerCallCount") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted progress callback (sol2): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeEngine.RunString(progressLuaScript);
                    std::cout << "DLL-hosted progress callback (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << " callCount=" << luaBridgeEngine.GetGlobalInt("callCount") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted progress callback (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeLegacyEngine.RunString(progressLuaScript);
                    std::cout << "DLL-hosted progress callback (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << " callCount=" << luaBridgeLegacyEngine.GetGlobalInt("callCount") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted progress callback (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* progressChaiScript =
                    "global callCount = 0;\n"
                    "global lastCurrentByte = 0;\n"
                    "def onProgress(currentByte, totalByte, percentage) {\n"
                    "    callCount = callCount + 1;\n"
                    "    lastCurrentByte = currentByte;\n"
                    "    return true;\n"
                    "}\n"
                    "cryptoApi.EncryptFileWithProgress(\"dllprogresstest\", \"dllrunner_progress_test_in.bin\", \"dllrunner_progress_test_enc.bin\", onProgress);\n"
                    "global ok = (callCount >= 3) && (lastCurrentByte == 5120);\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllCryptoApi(&scriptCryptoApi);
                    chaiEngine.RunString(progressChaiScript);
                    std::cout << "DLL-hosted progress callback (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << " callCount=" << chaiEngine.GetGlobalInt("callCount") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted progress callback (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* progressPythonScript =
                    "callCount = 0\n"
                    "lastCurrentByte = 0\n"
                    "def onProgress(currentByte, totalByte, percentage):\n"
                    "    global callCount, lastCurrentByte\n"
                    "    callCount = callCount + 1\n"
                    "    lastCurrentByte = currentByte\n"
                    "    return True\n"
                    "cryptoApi.EncryptFileWithProgress(\"dllprogresstest\", \"dllrunner_progress_test_in.bin\", \"dllrunner_progress_test_enc.bin\", onProgress)\n"
                    "ok = (callCount >= 3) and (lastCurrentByte == 5120)\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllCryptoApi(&scriptCryptoApi);
                    pythonEngine.RunString(progressPythonScript);
                    std::cout << "DLL-hosted progress callback (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << " callCount=" << pythonEngine.GetGlobalInt("callCount") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted progress callback (Python): FAILED exception " << ex.what() << std::endl;
                }

                std::remove(progressInputPath);
                std::remove(progressEncPath);

                // Remaining script test families per the 2026-09-22 parity audit
                // ([[project_runner_parity_audit_findings]]): symmetric EncryptString/
                // DecryptString, asymmetric RSA round trip, signature Sign/Verify, ECDH/X25519 key
                // agreement, random byte generation, PGP clear-sign/verify, and PGP wrapper (real
                // GnuPG) availability -- reuses the SAME scriptCryptoApi/scriptPgpEngine/
                // scriptPgpEngineWrapper DLL-hosted facade instances the hash+PGP demo above just
                // exercised, over the SAME pre-injected globals ("cryptoApi"/"pgpEngine"/
                // "pgpEngineWrapper"). CScriptCryptoApiDll/CScriptPgpEngineDll's method surface was
                // extended (2026-09-26) specifically to make this possible -- see those classes' own
                // header comments.
                const char* encryptDecryptLuaScript =
                    "local password = \"s3cr3t-dllrunner-lua-password\"\n"
                    "local plaintext = \"Hello from DLL Lua!\"\n"
                    "local ciphertext = cryptoApi:EncryptString(password, plaintext)\n"
                    "local decrypted = cryptoApi:DecryptString(password, ciphertext)\n"
                    "ok = (decrypted == plaintext)\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaEngine.RunString(encryptDecryptLuaScript);
                    std::cout << "DLL-hosted scripting EncryptDecrypt (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting EncryptDecrypt (sol2): FAILED exception " << ex.what() << std::endl;
                }

                const char* encryptDecryptLuaBridgeScript =
                    "local password = \"s3cr3t-dllrunner-luabridge-password\"\n"
                    "local plaintext = \"Hello from DLL LuaBridge!\"\n"
                    "local ciphertext = cryptoApi:EncryptString(password, plaintext)\n"
                    "local decrypted = cryptoApi:DecryptString(password, ciphertext)\n"
                    "ok = (decrypted == plaintext)\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeEngine.RunString(encryptDecryptLuaBridgeScript);
                    std::cout << "DLL-hosted scripting EncryptDecrypt (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting EncryptDecrypt (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeLegacyEngine.RunString(encryptDecryptLuaBridgeScript);
                    std::cout << "DLL-hosted scripting EncryptDecrypt (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting EncryptDecrypt (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* encryptDecryptChaiScript =
                    "var password = \"s3cr3t-dllrunner-chaiscript-password\";\n"
                    "var plaintext = \"Hello from DLL ChaiScript!\";\n"
                    "var ciphertext = cryptoApi.EncryptString(password, plaintext);\n"
                    "var decrypted = cryptoApi.DecryptString(password, ciphertext);\n"
                    "global ok = (decrypted == plaintext);\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllCryptoApi(&scriptCryptoApi);
                    chaiEngine.RunString(encryptDecryptChaiScript);
                    std::cout << "DLL-hosted scripting EncryptDecrypt (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting EncryptDecrypt (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* encryptDecryptPythonScript =
                    "password = \"s3cr3t-dllrunner-python-password\"\n"
                    "plaintext = \"Hello from DLL Python!\"\n"
                    "ciphertext = cryptoApi.EncryptString(password, plaintext)\n"
                    "decrypted = cryptoApi.DecryptString(password, ciphertext)\n"
                    "ok = (decrypted == plaintext)\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllCryptoApi(&scriptCryptoApi);
                    pythonEngine.RunString(encryptDecryptPythonScript);
                    std::cout << "DLL-hosted scripting EncryptDecrypt (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting EncryptDecrypt (Python): FAILED exception " << ex.what() << std::endl;
                }

                const char* asymmetricLuaScript =
                    "cryptoApi:GenerateAsymmetricKeyPair()\n"
                    "local plaintext = \"RSA round trip via DLL Lua\"\n"
                    "local inputBytes = ToBytes(plaintext)\n"
                    "local ciphertext = cryptoApi:EncryptWithPublicKey(inputBytes)\n"
                    "local decryptedBytes = cryptoApi:DecryptWithPrivateKey(ciphertext)\n"
                    "local chars = {}\n"
                    "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
                    "ok = (table.concat(chars) == plaintext) and (#ciphertext == cryptoApi:GetAsymmetricCiphertextSize())\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaEngine.RunString(asymmetricLuaScript);
                    std::cout << "DLL-hosted scripting Asymmetric (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Asymmetric (sol2): FAILED exception " << ex.what() << std::endl;
                }

                const char* asymmetricLuaBridgeScript =
                    "cryptoApi:GenerateAsymmetricKeyPair()\n"
                    "local plaintext = \"RSA round trip via DLL LuaBridge\"\n"
                    "local inputBytes = {}\n"
                    "for i = 1, #plaintext do inputBytes[i] = string.byte(plaintext, i) end\n"
                    "local ciphertext = cryptoApi:EncryptWithPublicKey(inputBytes)\n"
                    "local decryptedBytes = cryptoApi:DecryptWithPrivateKey(ciphertext)\n"
                    "local chars = {}\n"
                    "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
                    "ok = (table.concat(chars) == plaintext) and (#ciphertext == cryptoApi:GetAsymmetricCiphertextSize())\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeEngine.RunString(asymmetricLuaBridgeScript);
                    std::cout << "DLL-hosted scripting Asymmetric (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Asymmetric (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeLegacyEngine.RunString(asymmetricLuaBridgeScript);
                    std::cout << "DLL-hosted scripting Asymmetric (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Asymmetric (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* asymmetricChaiScript =
                    "cryptoApi.GenerateAsymmetricKeyPair();\n"
                    "var plaintext = \"RSA round trip via DLL ChaiScript\";\n"
                    "var inputBytes = ToBytes(plaintext);\n"
                    "var ciphertext = cryptoApi.EncryptWithPublicKey(inputBytes);\n"
                    "var decryptedBytes = cryptoApi.DecryptWithPrivateKey(ciphertext);\n"
                    "var decryptedText = ToStringFromBytes(decryptedBytes);\n"
                    "global ok = (decryptedText == plaintext) && (ciphertext.size() == cryptoApi.GetAsymmetricCiphertextSize());\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllCryptoApi(&scriptCryptoApi);
                    chaiEngine.RunString(asymmetricChaiScript);
                    std::cout << "DLL-hosted scripting Asymmetric (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Asymmetric (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* asymmetricPythonScript =
                    "cryptoApi.GenerateAsymmetricKeyPair()\n"
                    "plaintext = \"RSA round trip via DLL Python\"\n"
                    "inputBytes = ToBytes(plaintext)\n"
                    "ciphertext = cryptoApi.EncryptWithPublicKey(inputBytes)\n"
                    "decryptedBytes = cryptoApi.DecryptWithPrivateKey(ciphertext)\n"
                    "decryptedText = ToStringFromBytes(decryptedBytes)\n"
                    "ok = (decryptedText == plaintext) and (len(ciphertext) == cryptoApi.GetAsymmetricCiphertextSize())\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllCryptoApi(&scriptCryptoApi);
                    pythonEngine.RunString(asymmetricPythonScript);
                    std::cout << "DLL-hosted scripting Asymmetric (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Asymmetric (Python): FAILED exception " << ex.what() << std::endl;
                }

                const char* signatureLuaScript =
                    "cryptoApi:GenerateSignatureKeyPair()\n"
                    "local message = \"Sign this message from DLL Lua\"\n"
                    "local inputBytes = ToBytes(message)\n"
                    "local signature = cryptoApi:SignBuffer(inputBytes)\n"
                    "ok = cryptoApi:VerifyBuffer(inputBytes, signature) and (#signature == cryptoApi:GetSignatureSize())\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaEngine.RunString(signatureLuaScript);
                    std::cout << "DLL-hosted scripting Signature (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Signature (sol2): FAILED exception " << ex.what() << std::endl;
                }

                const char* signatureLuaBridgeScript =
                    "cryptoApi:GenerateSignatureKeyPair()\n"
                    "local message = \"Sign this message from DLL LuaBridge\"\n"
                    "local inputBytes = {}\n"
                    "for i = 1, #message do inputBytes[i] = string.byte(message, i) end\n"
                    "local signature = cryptoApi:SignBuffer(inputBytes)\n"
                    "ok = cryptoApi:VerifyBuffer(inputBytes, signature) and (#signature == cryptoApi:GetSignatureSize())\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeEngine.RunString(signatureLuaBridgeScript);
                    std::cout << "DLL-hosted scripting Signature (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Signature (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeLegacyEngine.RunString(signatureLuaBridgeScript);
                    std::cout << "DLL-hosted scripting Signature (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Signature (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* signatureChaiScript =
                    "cryptoApi.GenerateSignatureKeyPair();\n"
                    "var message = \"Sign this message from DLL ChaiScript\";\n"
                    "var inputBytes = ToBytes(message);\n"
                    "var signature = cryptoApi.SignBuffer(inputBytes);\n"
                    "global ok = cryptoApi.VerifyBuffer(inputBytes, signature) && (signature.size() == cryptoApi.GetSignatureSize());\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllCryptoApi(&scriptCryptoApi);
                    chaiEngine.RunString(signatureChaiScript);
                    std::cout << "DLL-hosted scripting Signature (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Signature (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* signaturePythonScript =
                    "cryptoApi.GenerateSignatureKeyPair()\n"
                    "message = \"Sign this message from DLL Python\"\n"
                    "inputBytes = ToBytes(message)\n"
                    "signature = cryptoApi.SignBuffer(inputBytes)\n"
                    "ok = cryptoApi.VerifyBuffer(inputBytes, signature) and (len(signature) == cryptoApi.GetSignatureSize())\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllCryptoApi(&scriptCryptoApi);
                    pythonEngine.RunString(signaturePythonScript);
                    std::cout << "DLL-hosted scripting Signature (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Signature (Python): FAILED exception " << ex.what() << std::endl;
                }

                // KeyAgreement: now a real two-party exchange (previously SKIPPED here, unlike
                // LibRunner's equivalent block, for exactly the reason this comment used to give --
                // SetDllCryptoApi alone only ever injects one fixed global named "cryptoApi" per
                // engine). scriptCryptoApiBob wraps the SEPARATE pScriptCryptoApiBob instance
                // obtained above (a second, genuinely independent CreateCryptoApi() call inside the
                // DLL, not a second handle to the same object) and is injected via the new
                // SetDllCryptoApiBob setter as a second global, "cryptoApiBob" -- so "cryptoApi" and
                // "cryptoApiBob" play alice/bob exactly like LibRunner's two CryptoApi.new()/
                // CryptoApi() instances do.
                if (pScriptCryptoApiBob != nullptr)
                {
                    CryptoApiNS::CScriptCryptoApiDll scriptCryptoApiBob(pScriptCryptoApiBob);

                    const char* keyAgreementLuaScript =
                        "cryptoApi:GenerateKeyAgreementKeyPair()\n"
                        "cryptoApiBob:GenerateKeyAgreementKeyPair()\n"
                        "local alicePublic = cryptoApi:ExportKeyAgreementPublicKey()\n"
                        "local bobPublic = cryptoApiBob:ExportKeyAgreementPublicKey()\n"
                        "local aliceSecret = cryptoApi:DeriveSharedSecret(bobPublic)\n"
                        "local bobSecret = cryptoApiBob:DeriveSharedSecret(alicePublic)\n"
                        "ok = (#aliceSecret == #bobSecret) and (#aliceSecret == cryptoApi:GetSharedSecretSize())\n"
                        "for i = 1, #aliceSecret do\n"
                        "    if aliceSecret[i] ~= bobSecret[i] then ok = false end\n"
                        "end\n";

                    try
                    {
                        CryptoApiNS::CLuaScriptEngineSol luaEngine;
                        luaEngine.SetDllCryptoApi(&scriptCryptoApi);
                        luaEngine.SetDllCryptoApiBob(&scriptCryptoApiBob);
                        luaEngine.RunString(keyAgreementLuaScript);
                        std::cout << "DLL-hosted scripting KeyAgreement (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                    }
                    catch (const std::exception& ex)
                    {
                        std::cout << "DLL-hosted scripting KeyAgreement (sol2): FAILED exception " << ex.what() << std::endl;
                    }

                    try
                    {
                        CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                        luaBridgeEngine.SetDllCryptoApi(&scriptCryptoApi);
                        luaBridgeEngine.SetDllCryptoApiBob(&scriptCryptoApiBob);
                        luaBridgeEngine.RunString(keyAgreementLuaScript);
                        std::cout << "DLL-hosted scripting KeyAgreement (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                    }
                    catch (const std::exception& ex)
                    {
                        std::cout << "DLL-hosted scripting KeyAgreement (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                    }

                    try
                    {
                        CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                        luaBridgeLegacyEngine.SetDllCryptoApi(&scriptCryptoApi);
                        luaBridgeLegacyEngine.SetDllCryptoApiBob(&scriptCryptoApiBob);
                        luaBridgeLegacyEngine.RunString(keyAgreementLuaScript);
                        std::cout << "DLL-hosted scripting KeyAgreement (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                    }
                    catch (const std::exception& ex)
                    {
                        std::cout << "DLL-hosted scripting KeyAgreement (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                    }

                    const char* keyAgreementChaiScript =
                        "cryptoApi.GenerateKeyAgreementKeyPair();\n"
                        "cryptoApiBob.GenerateKeyAgreementKeyPair();\n"
                        "var alicePublic = cryptoApi.ExportKeyAgreementPublicKey();\n"
                        "var bobPublic = cryptoApiBob.ExportKeyAgreementPublicKey();\n"
                        "var aliceSecret = cryptoApi.DeriveSharedSecret(bobPublic);\n"
                        "var bobSecret = cryptoApiBob.DeriveSharedSecret(alicePublic);\n"
                        "global ok = (aliceSecret.size() == bobSecret.size()) && (aliceSecret.size() == cryptoApi.GetSharedSecretSize());\n"
                        "for (auto i = 0; i < aliceSecret.size(); ++i) {\n"
                        "    if (aliceSecret[i] != bobSecret[i]) { ok = false; }\n"
                        "}\n";

                    try
                    {
                        CryptoApiNS::CChaiScriptEngine chaiEngine;
                        chaiEngine.SetDllCryptoApi(&scriptCryptoApi);
                        chaiEngine.SetDllCryptoApiBob(&scriptCryptoApiBob);
                        chaiEngine.RunString(keyAgreementChaiScript);
                        std::cout << "DLL-hosted scripting KeyAgreement (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                    }
                    catch (const std::exception& ex)
                    {
                        std::cout << "DLL-hosted scripting KeyAgreement (ChaiScript): FAILED exception " << ex.what() << std::endl;
                    }

                    const char* keyAgreementPythonScript =
                        "cryptoApi.GenerateKeyAgreementKeyPair()\n"
                        "cryptoApiBob.GenerateKeyAgreementKeyPair()\n"
                        "alicePublic = cryptoApi.ExportKeyAgreementPublicKey()\n"
                        "bobPublic = cryptoApiBob.ExportKeyAgreementPublicKey()\n"
                        "aliceSecret = cryptoApi.DeriveSharedSecret(bobPublic)\n"
                        "bobSecret = cryptoApiBob.DeriveSharedSecret(alicePublic)\n"
                        "ok = (len(aliceSecret) == len(bobSecret)) and (len(aliceSecret) == cryptoApi.GetSharedSecretSize())\n"
                        "for i in range(len(aliceSecret)):\n"
                        "    if aliceSecret[i] != bobSecret[i]:\n"
                        "        ok = False\n";

                    try
                    {
                        CryptoApiNS::CPythonScriptEngine pythonEngine;
                        pythonEngine.SetDllCryptoApi(&scriptCryptoApi);
                        pythonEngine.SetDllCryptoApiBob(&scriptCryptoApiBob);
                        pythonEngine.RunString(keyAgreementPythonScript);
                        std::cout << "DLL-hosted scripting KeyAgreement (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                    }
                    catch (const std::exception& ex)
                    {
                        std::cout << "DLL-hosted scripting KeyAgreement (Python): FAILED exception " << ex.what() << std::endl;
                    }
                }
                else
                {
                    std::cout << "DLL-hosted scripting KeyAgreement: SKIPPED for all 5 engines (could not obtain a second ICryptoApi instance from the DLL)" << std::endl;
                }

                const char* randomLuaScript =
                    "local randomBytes = cryptoApi:GenerateRandomBytes(32)\n"
                    "ok = (#randomBytes == 32)\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaEngine.RunString(randomLuaScript);
                    std::cout << "DLL-hosted scripting Random (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Random (sol2): FAILED exception " << ex.what() << std::endl;
                }

                const char* randomLuaBridgeScript =
                    "local randomBytes = cryptoApi:GenerateRandomBytes(32)\n"
                    "ok = (#randomBytes == 32)\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeEngine.RunString(randomLuaBridgeScript);
                    std::cout << "DLL-hosted scripting Random (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Random (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllCryptoApi(&scriptCryptoApi);
                    luaBridgeLegacyEngine.RunString(randomLuaBridgeScript);
                    std::cout << "DLL-hosted scripting Random (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Random (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* randomChaiScript =
                    "var randomBytes = cryptoApi.GenerateRandomBytes(32);\n"
                    "global ok = (randomBytes.size() == 32);\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllCryptoApi(&scriptCryptoApi);
                    chaiEngine.RunString(randomChaiScript);
                    std::cout << "DLL-hosted scripting Random (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Random (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* randomPythonScript =
                    "randomBytes = cryptoApi.GenerateRandomBytes(32)\n"
                    "ok = (len(randomBytes) == 32)\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllCryptoApi(&scriptCryptoApi);
                    pythonEngine.RunString(randomPythonScript);
                    std::cout << "DLL-hosted scripting Random (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Random (Python): FAILED exception " << ex.what() << std::endl;
                }

                const char* pgpSignVerifyLuaScript =
                    "local message = \"This clear-signed message comes from DLL Lua.\"\n"
                    "local signed = pgpEngine:ClearSignString(\"ScriptTestPassword123\", message)\n"
                    "ok = pgpEngine:VerifyClearSignedString(signed)\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllPgpEngine(&scriptPgpEngine);
                    luaEngine.RunString(pgpSignVerifyLuaScript);
                    std::cout << "DLL-hosted scripting PgpSignVerify (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpSignVerify (sol2): FAILED exception " << ex.what() << std::endl;
                }

                const char* pgpSignVerifyLuaBridgeScript =
                    "local message = \"This clear-signed message comes from DLL LuaBridge.\"\n"
                    "local signed = pgpEngine:ClearSignString(\"ScriptTestPassword123\", message)\n"
                    "ok = pgpEngine:VerifyClearSignedString(signed)\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllPgpEngine(&scriptPgpEngine);
                    luaBridgeEngine.RunString(pgpSignVerifyLuaBridgeScript);
                    std::cout << "DLL-hosted scripting PgpSignVerify (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpSignVerify (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllPgpEngine(&scriptPgpEngine);
                    luaBridgeLegacyEngine.RunString(pgpSignVerifyLuaBridgeScript);
                    std::cout << "DLL-hosted scripting PgpSignVerify (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpSignVerify (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* pgpSignVerifyChaiScript =
                    "var message = \"This clear-signed message comes from DLL ChaiScript.\";\n"
                    "var signedMessage = pgpEngine.ClearSignString(\"ScriptTestPassword123\", message);\n"
                    "global ok = pgpEngine.VerifyClearSignedString(signedMessage);\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllPgpEngine(&scriptPgpEngine);
                    chaiEngine.RunString(pgpSignVerifyChaiScript);
                    std::cout << "DLL-hosted scripting PgpSignVerify (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpSignVerify (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* pgpSignVerifyPythonScript =
                    "message = \"This clear-signed message comes from DLL Python.\"\n"
                    "signedMessage = pgpEngine.ClearSignString(\"ScriptTestPassword123\", message)\n"
                    "ok = pgpEngine.VerifyClearSignedString(signedMessage)\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllPgpEngine(&scriptPgpEngine);
                    pythonEngine.RunString(pgpSignVerifyPythonScript);
                    std::cout << "DLL-hosted scripting PgpSignVerify (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpSignVerify (Python): FAILED exception " << ex.what() << std::endl;
                }

                const char* pgpWrapperAvailabilityLuaScript =
                    "gnupgAvailable = pgpEngineWrapper:IsGnuPgAvailable()\n"
                    "ok = true\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    luaEngine.RunString(pgpWrapperAvailabilityLuaScript);
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (sol2): PASSED (GnuPG available=" << (luaEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (sol2): FAILED exception " << ex.what() << std::endl;
                }

                const char* pgpWrapperAvailabilityLuaBridgeScript =
                    "gnupgAvailable = pgpEngineWrapper:IsGnuPgAvailable()\n"
                    "ok = true\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    luaBridgeEngine.RunString(pgpWrapperAvailabilityLuaBridgeScript);
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (LuaBridge3): PASSED (GnuPG available=" << (luaBridgeEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    luaBridgeLegacyEngine.RunString(pgpWrapperAvailabilityLuaBridgeScript);
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (LuaBridge 2.10): PASSED (GnuPG available=" << (luaBridgeLegacyEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* pgpWrapperAvailabilityChaiScript =
                    "global gnupgAvailable = pgpEngineWrapper.IsGnuPgAvailable();\n"
                    "global ok = true;\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    chaiEngine.RunString(pgpWrapperAvailabilityChaiScript);
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (ChaiScript): PASSED (GnuPG available=" << (chaiEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* pgpWrapperAvailabilityPythonScript =
                    "gnupgAvailable = pgpEngineWrapper.IsGnuPgAvailable()\n"
                    "ok = True\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllPgpEngineWrapper(&scriptPgpEngineWrapper);
                    pythonEngine.RunString(pgpWrapperAvailabilityPythonScript);
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (Python): PASSED (GnuPG available=" << (pythonEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting PgpWrapperAvailability (Python): FAILED exception " << ex.what() << std::endl;
                }
            }

            if (pScriptCryptoApi)
            {
                pCryptoApiDllLoader->DestroyCryptoApiObject(pScriptCryptoApi);
            }
            if (pScriptCryptoApiBob)
            {
                pCryptoApiDllLoader->DestroyCryptoApiObject(pScriptCryptoApiBob);
            }
            if (pScriptPgpEngine)
            {
                pCryptoApiDllLoader->DestroyPgpEngineObject(pScriptPgpEngine);
            }
            if (pScriptPgpEngineWrapper)
            {
                pCryptoApiDllLoader->DestroyPgpEngineWrapperObject(pScriptPgpEngineWrapper);
            }

            // Scripting via the DLL, continued: Certificate/CMS/Timestamp facades over the SAME
            // loaded CryptoAPI.dll, same reduced-surface *Dll classes CScriptCertificateManagerDll.h
            // etc. document (GetLastPrivateKeyPem's own "stash secondary output" pattern, plain-int
            // algorithm parameters, VerifyDetached with no trust-root parameter at all here). Same
            // pre-injected-global convention as cryptoApi/pgpEngine above (SetDllCertificateManager/
            // SetDllCmsService/SetDllTimestampService -> "certificateManager"/"cmsService"/
            // "timestampService"), so the scripts below match ScriptEngineTester.cpp's own
            // RunLuaScriptCertificateTest family almost exactly, just without the
            // "CertificateManager.new()"/"CertificateManager()" constructor call.
            CryptoApiNS::ICertificateManager* pScriptCertificateManager = pCryptoApiDllLoader->GetCertificateManagerObject();
            CryptoApiNS::ICmsService* pScriptCmsService = pCryptoApiDllLoader->GetCmsServiceObject();
            CryptoApiNS::ITimestampService* pScriptTimestampService = pCryptoApiDllLoader->GetTimestampServiceObject();

            if (pScriptCertificateManager && pScriptCmsService && pScriptTimestampService)
            {
                std::cout << std::endl;

                CryptoApiNS::CScriptCertificateManagerDll scriptCertificateManager(pScriptCertificateManager);
                CryptoApiNS::CScriptCmsServiceDll scriptCmsService(pScriptCmsService);
                CryptoApiNS::CScriptTimestampServiceDll scriptTimestampService(pScriptTimestampService);

                const char* luaCertScript =
                    "local certDer = certificateManager:CreateSelfSignedCertificate(\"dllscripttest-lua.example.com\", 0, 30, 0)\n"
                    "local info = certificateManager:GetCertificateInfoText(certDer)\n"
                    "local certOk = (#certDer > 0) and (#info > 0)\n"
                    "local privateKeyPem = certificateManager:GetLastPrivateKeyPem()\n"
                    "local data = ToBytes(\"CMS test data from DLL Lua\")\n"
                    "local cmsDer = cmsService:SignDetached(data, certDer, privateKeyPem, 0)\n"
                    "local verifyResult = cmsService:VerifyDetached(data, cmsDer)\n"
                    "local cmsOk = (verifyResult == 0)\n"
                    "local digest = ToBytes(\"0123456789012345678901234567890a\")\n"
                    "local requestDer = timestampService:CreateTimestampRequest(digest, 0)\n"
                    "local tsOk = (#requestDer > 0)\n"
                    "ok = certOk and cmsOk and tsOk\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineSol luaEngine;
                    luaEngine.SetDllCertificateManager(&scriptCertificateManager);
                    luaEngine.SetDllCmsService(&scriptCmsService);
                    luaEngine.SetDllTimestampService(&scriptTimestampService);
                    luaEngine.RunString(luaCertScript);
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (sol2): FAILED exception " << ex.what() << std::endl;
                }

                const char* luaBridgeCertScript =
                    "local certDer = certificateManager:CreateSelfSignedCertificate(\"dllscripttest-luabridge.example.com\", 0, 30, 0)\n"
                    "local info = certificateManager:GetCertificateInfoText(certDer)\n"
                    "local certOk = (#certDer > 0) and (#info > 0)\n"
                    "local privateKeyPem = certificateManager:GetLastPrivateKeyPem()\n"
                    "local message = \"CMS test data from DLL LuaBridge3\"\n"
                    "local data = {}\n"
                    "for i = 1, #message do data[i] = string.byte(message, i) end\n"
                    "local cmsDer = cmsService:SignDetached(data, certDer, privateKeyPem, 0)\n"
                    "local verifyResult = cmsService:VerifyDetached(data, cmsDer)\n"
                    "local cmsOk = (verifyResult == 0)\n"
                    "local digestMsg = \"0123456789012345678901234567890a\"\n"
                    "local digest = {}\n"
                    "for i = 1, #digestMsg do digest[i] = string.byte(digestMsg, i) end\n"
                    "local requestDer = timestampService:CreateTimestampRequest(digest, 0)\n"
                    "local tsOk = (#requestDer > 0)\n"
                    "ok = certOk and cmsOk and tsOk\n";

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                    luaBridgeEngine.SetDllCertificateManager(&scriptCertificateManager);
                    luaBridgeEngine.SetDllCmsService(&scriptCmsService);
                    luaBridgeEngine.SetDllTimestampService(&scriptTimestampService);
                    luaBridgeEngine.RunString(luaBridgeCertScript);
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (LuaBridge3): FAILED exception " << ex.what() << std::endl;
                }

                try
                {
                    CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                    luaBridgeLegacyEngine.SetDllCertificateManager(&scriptCertificateManager);
                    luaBridgeLegacyEngine.SetDllCmsService(&scriptCmsService);
                    luaBridgeLegacyEngine.SetDllTimestampService(&scriptTimestampService);
                    luaBridgeLegacyEngine.RunString(luaBridgeCertScript);
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
                }

                const char* chaiCertScript =
                    "var certDer = certificateManager.CreateSelfSignedCertificate(\"dllscripttest-chai.example.com\", 0, 30, 0);\n"
                    "var info = certificateManager.GetCertificateInfoText(certDer);\n"
                    "var certOk = (certDer.size() > 0) && (info.size() > 0);\n"
                    "var privateKeyPem = certificateManager.GetLastPrivateKeyPem();\n"
                    "var data = ToBytes(\"CMS test data from DLL ChaiScript\");\n"
                    "var cmsDer = cmsService.SignDetached(data, certDer, privateKeyPem, 0);\n"
                    "var verifyResult = cmsService.VerifyDetached(data, cmsDer);\n"
                    "var cmsOk = (verifyResult == 0);\n"
                    "var digest = ToBytes(\"0123456789012345678901234567890a\");\n"
                    "var requestDer = timestampService.CreateTimestampRequest(digest, 0);\n"
                    "var tsOk = (requestDer.size() > 0);\n"
                    "global ok = certOk && cmsOk && tsOk;\n";

                try
                {
                    CryptoApiNS::CChaiScriptEngine chaiEngine;
                    chaiEngine.SetDllCertificateManager(&scriptCertificateManager);
                    chaiEngine.SetDllCmsService(&scriptCmsService);
                    chaiEngine.SetDllTimestampService(&scriptTimestampService);
                    chaiEngine.RunString(chaiCertScript);
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (ChaiScript): FAILED exception " << ex.what() << std::endl;
                }

                const char* pythonCertScript =
                    "certDer = certificateManager.CreateSelfSignedCertificate(\"dllscripttest-python.example.com\", 0, 30, 0)\n"
                    "info = certificateManager.GetCertificateInfoText(certDer)\n"
                    "certOk = (len(certDer) > 0) and (len(info) > 0)\n"
                    "privateKeyPem = certificateManager.GetLastPrivateKeyPem()\n"
                    "data = ToBytes(\"CMS test data from DLL Python\")\n"
                    "cmsDer = cmsService.SignDetached(data, certDer, privateKeyPem, 0)\n"
                    "verifyResult = cmsService.VerifyDetached(data, cmsDer)\n"
                    "cmsOk = (verifyResult == 0)\n"
                    "digest = ToBytes(\"0123456789012345678901234567890a\")\n"
                    "requestDer = timestampService.CreateTimestampRequest(digest, 0)\n"
                    "tsOk = (len(requestDer) > 0)\n"
                    "ok = certOk and cmsOk and tsOk\n";

                try
                {
                    CryptoApiNS::CPythonScriptEngine pythonEngine;
                    pythonEngine.SetDllCertificateManager(&scriptCertificateManager);
                    pythonEngine.SetDllCmsService(&scriptCmsService);
                    pythonEngine.SetDllTimestampService(&scriptTimestampService);
                    pythonEngine.RunString(pythonCertScript);
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
                }
                catch (const std::exception& ex)
                {
                    std::cout << "DLL-hosted scripting Certificate/CMS/Timestamp (Python): FAILED exception " << ex.what() << std::endl;
                }
            }

            if (pScriptCertificateManager)
            {
                pCryptoApiDllLoader->DestroyCertificateManagerObject(pScriptCertificateManager);
            }
            if (pScriptCmsService)
            {
                pCryptoApiDllLoader->DestroyCmsServiceObject(pScriptCmsService);
            }
            if (pScriptTimestampService)
            {
                pCryptoApiDllLoader->DestroyTimestampServiceObject(pScriptTimestampService);
            }
        }

        delete pCryptoApiDllLoader;
    }
    catch (...)
    {

    }

    return 0;
}
// -----------------------------------------------------------------------------

int main()
{
    const std::vector<std::string> cliArgs = getUtf8CommandLineArgs();
    if (!cliArgs.empty())
    {
        CryptoApiNS::CCommandLineParser parser;
        parser.Parse(cliArgs);
        return runCliMode(parser);
    }

    return runAllTests();
}

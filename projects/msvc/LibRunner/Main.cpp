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

#include <shellapi.h>

#include "CryptoApi.h"
#include "CryptoApiTester.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"
#include "Cli/CommandLineParser.h"
#include "Utils/Utils.h"

#include "Scripts/ScriptCryptoApi.h"
#include "Scripts/ScriptPgpEngine.h"
#include "Scripts/ScriptPgpEngineWrapper.h"
#include "Scripts/ScriptCertificateManager.h"
#include "Scripts/ScriptCmsService.h"
#include "Scripts/ScriptTimestampService.h"
#include "Scripts/LuaScript/LuaScriptEngineSol.h"
#include "Scripts/LuaScript/LuaScriptEngineLuaBridge.h"
#include "Scripts/LuaScript/LuaScriptEngineLuaBridgeLegacy.h"
#include "Scripts/PythonScript/PythonScriptEngine.h"

// Linked here instead of via the project's Linker > Input > Additional Dependencies setting;
// the search path (LibBuilder's per-platform output directory) still comes from the project's
// Additional Library Directories, this only supplies the library's name.
#pragma comment(lib, "CryptoAPI_static.lib")

// Real Unicode command-line args (excludes argv[0]), converted to UTF-8 -- same reasoning as
// AppBuilder/DllRunner's own identical helper (see the AppRunner CLI harness plan).
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

// Phase 4 of the AppRunner CLI harness plan: LibRunner gets the IDENTICAL action set AppBuilder/
// DllRunner's own Main.cpp implement, dispatching through the static-lib-linked CCryptoApi/
// CPgpEngine directly (same in-process calling convention as AppBuilder, just linked from
// CryptoAPI_static.lib instead of compiling the SDK's own .cpp files directly).
int runCliActionHash(const CryptoApiNS::CCommandLineParser& parser)
{
    const std::string input = parser.GetString("input", "");
    CryptoApiNS::CCryptoApi cryptoApi;

    unsigned char digest[64];
    int digestSize = 0;
    const int status = cryptoApi.ComputeHashString( input.c_str(), static_cast<int>(input.size()),
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

int runCliActionEncryptString(const CryptoApiNS::CCommandLineParser& parser)
{
    const std::string password = parser.GetString("password", "");
    const std::string input = parser.GetString("input", "");
    CryptoApiNS::CCryptoApi cryptoApi;

    unsigned char cipherBuffer[8192];
    int cipherSize = 0;
    const int status = cryptoApi.EncryptString( password.c_str(), static_cast<int>(password.size()),
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

int runCliActionDecryptString(const CryptoApiNS::CCommandLineParser& parser)
{
    const std::string password = parser.GetString("password", "");
    const std::string input = parser.GetString("input", "");
    CryptoApiNS::CCryptoApi cryptoApi;

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
    const int status = cryptoApi.DecryptString( password.c_str(), static_cast<int>(password.size()),
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

int runCliActionPgpRoundtrip(const CryptoApiNS::CCommandLineParser& parser)
{
    const std::string userId = parser.GetString("userid", "CLI Test <cli-test@example.com>");
    const std::string password = parser.GetString("password", "");
    const std::string message = parser.GetString("message", "");

    CryptoApiNS::CPgpEngine pgpEngine;
    int status = pgpEngine.GenerateKeyPair( userId.c_str(), static_cast<int>(userId.size()),
                                            password.c_str(), static_cast<int>(password.size()));
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "GenerateKeyPair failed, status=" << status << std::endl;
        return 1;
    }

    char pubKeyArmored[16384];
    int pubKeySize = 0;
    status = pgpEngine.ExportPublicKeyArmored(sizeof(pubKeyArmored), pubKeyArmored, &pubKeySize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ExportPublicKeyArmored failed, status=" << status << std::endl;
        return 1;
    }

    status = pgpEngine.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(pubKeyArmored), pubKeySize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ImportPeerPublicKey failed, status=" << status << std::endl;
        return 1;
    }

    char encryptedArmored[16384];
    int encryptedSize = 0;
    status = pgpEngine.EncryptStringArmored( message.c_str(), static_cast<int>(message.size()),
                                             sizeof(encryptedArmored), encryptedArmored, &encryptedSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "EncryptStringArmored failed, status=" << status << std::endl;
        return 1;
    }

    unsigned char decryptedBuffer[16384];
    int decryptedSize = 0;
    status = pgpEngine.DecryptStringArmored( password.c_str(), static_cast<int>(password.size()),
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

// gpg.exe-style discrete PGP commands (AppRunner CLI harness plan, next phase after
// pgp-roundtrip above) -- same action set/semantics as AppBuilder/Main.cpp's own copy of these 8
// functions (see its own header comment for the full rationale). Static-lib-linked, so
// CryptoApiNS::CPgpEngineWrapper is constructed directly, same in-process pattern as pgp-roundtrip
// above and AppBuilder's own copy.
const char* pgpKeyHomeDefault = ".\\pgp-keyhome";

bool setUpPgpWrapper(const CryptoApiNS::CCommandLineParser& parser, CryptoApiNS::CPgpEngineWrapper& wrapper, std::string& keyHomeOut)
{
    keyHomeOut = parser.GetString("keyhome", pgpKeyHomeDefault);
    if (wrapper.SetHomeDir(keyHomeOut.c_str(), static_cast<int>(keyHomeOut.size())) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "SetHomeDir(" << keyHomeOut << ") failed" << std::endl;
        return false;
    }
    if (!wrapper.IsGnuPgAvailable())
    {
        std::cerr << "GnuPG (gpg.exe) not found on this machine -- pgp-* actions need a real, "
                     "locally installed GnuPG/Gpg4win" << std::endl;
        return false;
    }
    return true;
}
// -----------------------------------------------------------------------------

int runCliActionPgpCheck(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    const std::string keyHome = parser.GetString("keyhome", pgpKeyHomeDefault);
    if (wrapper.SetHomeDir(keyHome.c_str(), static_cast<int>(keyHome.size())) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "SetHomeDir(" << keyHome << ") failed" << std::endl;
        return 1;
    }
    const bool available = wrapper.IsGnuPgAvailable();
    std::cout << (available ? "GnuPG available: yes" : "GnuPG available: no") << std::endl;
    return available ? 0 : 6;
}
// -----------------------------------------------------------------------------

int runCliActionPgpGenKey(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    std::string keyHome;
    if (!setUpPgpWrapper(parser, wrapper, keyHome))
    {
        return 6;
    }

    const std::string userId = parser.GetString("userid", "CLI Test <cli-test@example.com>");
    const std::string password = parser.GetString("password", "");
    const int status = wrapper.GenerateKeyPair( userId.c_str(), static_cast<int>(userId.size()),
                                               password.c_str(), static_cast<int>(password.size()));
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "GenerateKeyPair failed, status=" << status << std::endl;
        return 1;
    }

    char keyId[32];
    wrapper.GetKeyId(keyId, sizeof(keyId));
    std::cout << "OK, key id: " << keyId << " (keyhome: " << keyHome << ")" << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionPgpListKeys(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    std::string keyHome;
    if (!setUpPgpWrapper(parser, wrapper, keyHome))
    {
        return 6;
    }

    char listing[16384];
    int listingSize = 0;
    const int status = wrapper.GetKeyringListing(sizeof(listing), listing, &listingSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "GetKeyringListing failed, status=" << status << std::endl;
        return 1;
    }
    std::cout << std::string(listing, static_cast<std::size_t>(listingSize)) << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionPgpExportKey(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    std::string keyHome;
    if (!setUpPgpWrapper(parser, wrapper, keyHome))
    {
        return 6;
    }

    if (wrapper.LoadOwnIdentity() != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "LoadOwnIdentity failed -- no (or more than one) identity in keyhome " << keyHome << std::endl;
        return 1;
    }

    char armored[16384];
    int armoredSize = 0;
    const int status = wrapper.ExportPublicKeyArmored(sizeof(armored), armored, &armoredSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ExportPublicKeyArmored failed, status=" << status << std::endl;
        return 1;
    }
    std::cout << std::string(armored, static_cast<std::size_t>(armoredSize)) << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionPgpEncrypt(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    std::string keyHome;
    if (!setUpPgpWrapper(parser, wrapper, keyHome))
    {
        return 6;
    }
    if (wrapper.LoadOwnIdentity() != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "LoadOwnIdentity failed -- run pgp-gen-key on this keyhome first" << std::endl;
        return 1;
    }

    char armoredPub[16384];
    int armoredPubSize = 0;
    if (wrapper.ExportPublicKeyArmored(sizeof(armoredPub), armoredPub, &armoredPubSize) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ExportPublicKeyArmored failed" << std::endl;
        return 1;
    }
    if (wrapper.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(armoredPub), armoredPubSize) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ImportPeerPublicKey(self) failed" << std::endl;
        return 1;
    }

    const std::string input = parser.GetString("input", "");
    char encrypted[16384];
    int encryptedSize = 0;
    const int status = wrapper.EncryptStringArmored( input.c_str(), static_cast<int>(input.size()),
                                                     sizeof(encrypted), encrypted, &encryptedSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "EncryptStringArmored failed, status=" << status << std::endl;
        return 1;
    }
    std::cout << std::string(encrypted, static_cast<std::size_t>(encryptedSize)) << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionPgpDecrypt(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    std::string keyHome;
    if (!setUpPgpWrapper(parser, wrapper, keyHome))
    {
        return 6;
    }
    if (wrapper.LoadOwnIdentity() != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "LoadOwnIdentity failed -- run pgp-gen-key on this keyhome first" << std::endl;
        return 1;
    }

    const std::string password = parser.GetString("password", "");
    const std::string input = parser.GetString("input", "");
    unsigned char plainBuffer[16384];
    int plainSize = 0;
    const int status = wrapper.DecryptStringArmored( password.c_str(), static_cast<int>(password.size()),
                                                     input.c_str(), static_cast<int>(input.size()),
                                                     sizeof(plainBuffer), plainBuffer, &plainSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "DecryptStringArmored failed, status=" << status << std::endl;
        return 1;
    }
    std::cout << std::string(reinterpret_cast<const char*>(plainBuffer), static_cast<std::size_t>(plainSize)) << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionPgpSign(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    std::string keyHome;
    if (!setUpPgpWrapper(parser, wrapper, keyHome))
    {
        return 6;
    }
    if (wrapper.LoadOwnIdentity() != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "LoadOwnIdentity failed -- run pgp-gen-key on this keyhome first" << std::endl;
        return 1;
    }

    const std::string password = parser.GetString("password", "");
    const std::string input = parser.GetString("input", "");
    char clearSigned[16384];
    int clearSignedSize = 0;
    const int status = wrapper.ClearSignString( password.c_str(), static_cast<int>(password.size()),
                                                input.c_str(), static_cast<int>(input.size()),
                                                sizeof(clearSigned), clearSigned, &clearSignedSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ClearSignString failed, status=" << status << std::endl;
        return 1;
    }
    std::cout << std::string(clearSigned, static_cast<std::size_t>(clearSignedSize)) << std::endl;
    return 0;
}
// -----------------------------------------------------------------------------

int runCliActionPgpVerify(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    std::string keyHome;
    if (!setUpPgpWrapper(parser, wrapper, keyHome))
    {
        return 6;
    }
    if (wrapper.LoadOwnIdentity() != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "LoadOwnIdentity failed -- run pgp-gen-key on this keyhome first" << std::endl;
        return 1;
    }

    char armoredPub[16384];
    int armoredPubSize = 0;
    if (wrapper.ExportPublicKeyArmored(sizeof(armoredPub), armoredPub, &armoredPubSize) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ExportPublicKeyArmored failed" << std::endl;
        return 1;
    }
    if (wrapper.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(armoredPub), armoredPubSize) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ImportPeerPublicKey(self) failed" << std::endl;
        return 1;
    }

    const std::string input = parser.GetString("input", "");
    bool isValid = false;
    const int status = wrapper.VerifyClearSignedString(input.c_str(), static_cast<int>(input.size()), &isValid);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "VerifyClearSignedString failed, status=" << status << std::endl;
        return 1;
    }
    std::cout << (isValid ? "VALID" : "INVALID") << std::endl;
    return isValid ? 0 : 7;
}
// -----------------------------------------------------------------------------

// Defined below (it's the exact sequence main() always ran unconditionally before the CLI existed).
// Forward-declared here so runCliAction's "run-tests" action can reach it.
int runAllTests();
// -----------------------------------------------------------------------------

// gpg.exe-style self-documentation ("gpg --dump-options"/"gpg --help") -- unlike the error path
// below (which only lists bare action NAMES), this also shows each action's expected arguments, so
// it doubles as this CLI's own usage reference.
int runCliActionListActions(void)
{
    std::cout <<
        "Desteklenen -action degerleri:\n"
        "\n"
        "Genel:\n"
        "  version                                        (arg yok)\n"
        "  list-actions                                    (arg yok, bu liste)\n"
        "  run-tests                                       (arg yok -- tam test suite'i kosturur)\n"
        "  hash                    -input TEXT\n"
        "  encrypt-string          -password X -input TEXT\n"
        "  decrypt-string          -password X -input BASE64\n"
        "\n"
        "PGP (CPgpEngine, static-lib, tek process icinde bundled demo):\n"
        "  pgp-roundtrip           [-userid ID] -password X -message TEXT\n"
        "\n"
        "PGP (CPgpEngineWrapper, static-lib, gpg.exe benzeri, kalici -keyhome ile ayri invocation'lar arasi):\n"
        "  pgp-check               [-keyhome DIR]\n"
        "  pgp-gen-key             [-keyhome DIR] [-userid ID] -password X\n"
        "  pgp-list-keys           [-keyhome DIR]\n"
        "  pgp-export-key          [-keyhome DIR]\n"
        "  pgp-encrypt             [-keyhome DIR] -password X -input TEXT\n"
        "  pgp-decrypt             [-keyhome DIR] -password X -input ARMORED\n"
        "  pgp-sign                [-keyhome DIR] -password X -input TEXT\n"
        "  pgp-verify              [-keyhome DIR] -input ARMORED\n"
        "\n"
        "-keyhome varsayilani: .\\pgp-keyhome (verilmezse). [] iceki argumanlar opsiyonel (kendi varsayilanlari var).\n";
    return 0;
}
// -----------------------------------------------------------------------------

int runCliAction(const CryptoApiNS::CCommandLineParser& parser)
{
    const std::string action = parser.GetString("action", "");
    if (action == "version")
    {
        std::cout << CryptoApiNS::CUtils::FormatBuildDate() << std::endl;
        return 0;
    }
    if (action == "hash")
    {
        return runCliActionHash(parser);
    }
    if (action == "encrypt-string")
    {
        return runCliActionEncryptString(parser);
    }
    if (action == "decrypt-string")
    {
        return runCliActionDecryptString(parser);
    }
    if (action == "pgp-roundtrip")
    {
        return runCliActionPgpRoundtrip(parser);
    }
    if (action == "pgp-check")
    {
        return runCliActionPgpCheck(parser);
    }
    if (action == "pgp-gen-key")
    {
        return runCliActionPgpGenKey(parser);
    }
    if (action == "pgp-list-keys")
    {
        return runCliActionPgpListKeys(parser);
    }
    if (action == "pgp-export-key")
    {
        return runCliActionPgpExportKey(parser);
    }
    if (action == "pgp-encrypt")
    {
        return runCliActionPgpEncrypt(parser);
    }
    if (action == "pgp-decrypt")
    {
        return runCliActionPgpDecrypt(parser);
    }
    if (action == "pgp-sign")
    {
        return runCliActionPgpSign(parser);
    }
    if (action == "pgp-verify")
    {
        return runCliActionPgpVerify(parser);
    }
    if (action == "run-tests")
    {
        return runAllTests();
    }
    if (action == "list-actions")
    {
        return runCliActionListActions();
    }

    std::cerr << "Unknown or missing -action. Supported actions: version, hash, encrypt-string, "
                 "decrypt-string, pgp-roundtrip, pgp-check, pgp-gen-key, pgp-list-keys, "
                 "pgp-export-key, pgp-encrypt, pgp-decrypt, pgp-sign, pgp-verify, run-tests, "
                 "list-actions (run -action list-actions for full usage)" << std::endl;
    return 2;
}
// -----------------------------------------------------------------------------

// The exact sequence main() always ran unconditionally before the CLI existed (native
// CCryptoApiTester suite + all 5 script engines' own demo/test suites) -- extracted here, unchanged,
// so it can be triggered explicitly via `-action run-tests` as well as by the original no-args
// fallback in main().
int runAllTests()
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

        // Remaining script test families per the 2026-09-22 parity audit
        // ([[project_runner_parity_audit_findings]]): symmetric EncryptString/DecryptString,
        // asymmetric RSA round trip, signature Sign/Verify, ECDH/X25519 key agreement, random byte
        // generation, PGP clear-sign/verify, and PGP wrapper (real GnuPG) availability -- same
        // scripts ScriptEngineTester.cpp's own RunXxxScriptYyyTest family already exercises
        // natively, shown here working from a statically-linked LibRunner build too, same
        // "Static-link ... (engine): PASSED/FAILED" convention as the blocks above.
        {
            std::cout << std::endl;

            const char* encryptDecryptLuaScript =
                "local api = CryptoApi.new()\n"
                "local password = \"s3cr3t-librunner-lua-password\"\n"
                "local plaintext = \"Hello from LibRunner Lua!\"\n"
                "local ciphertext = api:EncryptString(password, plaintext)\n"
                "local decrypted = api:DecryptString(password, ciphertext)\n"
                "ok = (decrypted == plaintext)\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(encryptDecryptLuaScript);
                std::cout << "Static-link scripting EncryptDecrypt (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting EncryptDecrypt (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* encryptDecryptLuaBridgeScript =
                "local api = CryptoApi()\n"
                "local password = \"s3cr3t-librunner-luabridge-password\"\n"
                "local plaintext = \"Hello from LibRunner LuaBridge!\"\n"
                "local ciphertext = api:EncryptString(password, plaintext)\n"
                "local decrypted = api:DecryptString(password, ciphertext)\n"
                "ok = (decrypted == plaintext)\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(encryptDecryptLuaBridgeScript);
                std::cout << "Static-link scripting EncryptDecrypt (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting EncryptDecrypt (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(encryptDecryptLuaBridgeScript);
                std::cout << "Static-link scripting EncryptDecrypt (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting EncryptDecrypt (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* encryptDecryptChaiScript =
                "var api = CryptoApi();\n"
                "var password = \"s3cr3t-librunner-chaiscript-password\";\n"
                "var plaintext = \"Hello from LibRunner ChaiScript!\";\n"
                "var ciphertext = api.EncryptString(password, plaintext);\n"
                "var decrypted = api.DecryptString(password, ciphertext);\n"
                "global ok = (decrypted == plaintext);\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(encryptDecryptChaiScript);
                std::cout << "Static-link scripting EncryptDecrypt (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting EncryptDecrypt (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* encryptDecryptPythonScript =
                "api = CryptoApi()\n"
                "password = \"s3cr3t-librunner-python-password\"\n"
                "plaintext = \"Hello from LibRunner Python!\"\n"
                "ciphertext = api.EncryptString(password, plaintext)\n"
                "decrypted = api.DecryptString(password, ciphertext)\n"
                "ok = (decrypted == plaintext)\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(encryptDecryptPythonScript);
                std::cout << "Static-link scripting EncryptDecrypt (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting EncryptDecrypt (Python): FAILED exception " << ex.what() << std::endl;
            }

            const char* asymmetricLuaScript =
                "local api = CryptoApi.new()\n"
                "api:GenerateAsymmetricKeyPair()\n"
                "local plaintext = \"RSA round trip via LibRunner Lua\"\n"
                "local inputBytes = ToBytes(plaintext)\n"
                "local ciphertext = api:EncryptWithPublicKey(inputBytes)\n"
                "local decryptedBytes = api:DecryptWithPrivateKey(ciphertext)\n"
                "local chars = {}\n"
                "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
                "ok = (table.concat(chars) == plaintext) and (#ciphertext == api:GetAsymmetricCiphertextSize())\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(asymmetricLuaScript);
                std::cout << "Static-link scripting Asymmetric (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Asymmetric (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* asymmetricLuaBridgeScript =
                "local api = CryptoApi()\n"
                "api:GenerateAsymmetricKeyPair()\n"
                "local plaintext = \"RSA round trip via LibRunner LuaBridge\"\n"
                "local inputBytes = {}\n"
                "for i = 1, #plaintext do inputBytes[i] = string.byte(plaintext, i) end\n"
                "local ciphertext = api:EncryptWithPublicKey(inputBytes)\n"
                "local decryptedBytes = api:DecryptWithPrivateKey(ciphertext)\n"
                "local chars = {}\n"
                "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
                "ok = (table.concat(chars) == plaintext) and (#ciphertext == api:GetAsymmetricCiphertextSize())\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(asymmetricLuaBridgeScript);
                std::cout << "Static-link scripting Asymmetric (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Asymmetric (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(asymmetricLuaBridgeScript);
                std::cout << "Static-link scripting Asymmetric (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Asymmetric (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* asymmetricChaiScript =
                "var api = CryptoApi();\n"
                "api.GenerateAsymmetricKeyPair();\n"
                "var plaintext = \"RSA round trip via LibRunner ChaiScript\";\n"
                "var inputBytes = ToBytes(plaintext);\n"
                "var ciphertext = api.EncryptWithPublicKey(inputBytes);\n"
                "var decryptedBytes = api.DecryptWithPrivateKey(ciphertext);\n"
                "var decryptedText = ToStringFromBytes(decryptedBytes);\n"
                "global ok = (decryptedText == plaintext) && (ciphertext.size() == api.GetAsymmetricCiphertextSize());\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(asymmetricChaiScript);
                std::cout << "Static-link scripting Asymmetric (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Asymmetric (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* asymmetricPythonScript =
                "api = CryptoApi()\n"
                "api.GenerateAsymmetricKeyPair()\n"
                "plaintext = \"RSA round trip via LibRunner Python\"\n"
                "inputBytes = ToBytes(plaintext)\n"
                "ciphertext = api.EncryptWithPublicKey(inputBytes)\n"
                "decryptedBytes = api.DecryptWithPrivateKey(ciphertext)\n"
                "decryptedText = ToStringFromBytes(decryptedBytes)\n"
                "ok = (decryptedText == plaintext) and (len(ciphertext) == api.GetAsymmetricCiphertextSize())\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(asymmetricPythonScript);
                std::cout << "Static-link scripting Asymmetric (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Asymmetric (Python): FAILED exception " << ex.what() << std::endl;
            }

            const char* signatureLuaScript =
                "local api = CryptoApi.new()\n"
                "api:GenerateSignatureKeyPair()\n"
                "local message = \"Sign this message from LibRunner Lua\"\n"
                "local inputBytes = ToBytes(message)\n"
                "local signature = api:SignBuffer(inputBytes)\n"
                "ok = api:VerifyBuffer(inputBytes, signature) and (#signature == api:GetSignatureSize())\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(signatureLuaScript);
                std::cout << "Static-link scripting Signature (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Signature (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* signatureLuaBridgeScript =
                "local api = CryptoApi()\n"
                "api:GenerateSignatureKeyPair()\n"
                "local message = \"Sign this message from LibRunner LuaBridge\"\n"
                "local inputBytes = {}\n"
                "for i = 1, #message do inputBytes[i] = string.byte(message, i) end\n"
                "local signature = api:SignBuffer(inputBytes)\n"
                "ok = api:VerifyBuffer(inputBytes, signature) and (#signature == api:GetSignatureSize())\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(signatureLuaBridgeScript);
                std::cout << "Static-link scripting Signature (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Signature (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(signatureLuaBridgeScript);
                std::cout << "Static-link scripting Signature (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Signature (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* signatureChaiScript =
                "var api = CryptoApi();\n"
                "api.GenerateSignatureKeyPair();\n"
                "var message = \"Sign this message from LibRunner ChaiScript\";\n"
                "var inputBytes = ToBytes(message);\n"
                "var signature = api.SignBuffer(inputBytes);\n"
                "global ok = api.VerifyBuffer(inputBytes, signature) && (signature.size() == api.GetSignatureSize());\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(signatureChaiScript);
                std::cout << "Static-link scripting Signature (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Signature (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* signaturePythonScript =
                "api = CryptoApi()\n"
                "api.GenerateSignatureKeyPair()\n"
                "message = \"Sign this message from LibRunner Python\"\n"
                "inputBytes = ToBytes(message)\n"
                "signature = api.SignBuffer(inputBytes)\n"
                "ok = api.VerifyBuffer(inputBytes, signature) and (len(signature) == api.GetSignatureSize())\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(signaturePythonScript);
                std::cout << "Static-link scripting Signature (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Signature (Python): FAILED exception " << ex.what() << std::endl;
            }

            const char* keyAgreementLuaScript =
                "local alice = CryptoApi.new()\n"
                "local bob = CryptoApi.new()\n"
                "alice:GenerateKeyAgreementKeyPair()\n"
                "bob:GenerateKeyAgreementKeyPair()\n"
                "local alicePublic = alice:ExportKeyAgreementPublicKey()\n"
                "local bobPublic = bob:ExportKeyAgreementPublicKey()\n"
                "local aliceSecret = alice:DeriveSharedSecret(bobPublic)\n"
                "local bobSecret = bob:DeriveSharedSecret(alicePublic)\n"
                "ok = (#aliceSecret == #bobSecret) and (#aliceSecret == alice:GetSharedSecretSize())\n"
                "for i = 1, #aliceSecret do\n"
                "    if aliceSecret[i] ~= bobSecret[i] then ok = false end\n"
                "end\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(keyAgreementLuaScript);
                std::cout << "Static-link scripting KeyAgreement (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting KeyAgreement (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* keyAgreementLuaBridgeScript =
                "local alice = CryptoApi()\n"
                "local bob = CryptoApi()\n"
                "alice:GenerateKeyAgreementKeyPair()\n"
                "bob:GenerateKeyAgreementKeyPair()\n"
                "local alicePublic = alice:ExportKeyAgreementPublicKey()\n"
                "local bobPublic = bob:ExportKeyAgreementPublicKey()\n"
                "local aliceSecret = alice:DeriveSharedSecret(bobPublic)\n"
                "local bobSecret = bob:DeriveSharedSecret(alicePublic)\n"
                "ok = (#aliceSecret == #bobSecret) and (#aliceSecret == alice:GetSharedSecretSize())\n"
                "for i = 1, #aliceSecret do\n"
                "    if aliceSecret[i] ~= bobSecret[i] then ok = false end\n"
                "end\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(keyAgreementLuaBridgeScript);
                std::cout << "Static-link scripting KeyAgreement (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting KeyAgreement (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(keyAgreementLuaBridgeScript);
                std::cout << "Static-link scripting KeyAgreement (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting KeyAgreement (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* keyAgreementChaiScript =
                "var alice = CryptoApi();\n"
                "var bob = CryptoApi();\n"
                "alice.GenerateKeyAgreementKeyPair();\n"
                "bob.GenerateKeyAgreementKeyPair();\n"
                "var alicePublic = alice.ExportKeyAgreementPublicKey();\n"
                "var bobPublic = bob.ExportKeyAgreementPublicKey();\n"
                "var aliceSecret = alice.DeriveSharedSecret(bobPublic);\n"
                "var bobSecret = bob.DeriveSharedSecret(alicePublic);\n"
                "global ok = (aliceSecret.size() == bobSecret.size()) && (aliceSecret.size() == alice.GetSharedSecretSize());\n"
                "for (auto i = 0; i < aliceSecret.size(); ++i) {\n"
                "    if (aliceSecret[i] != bobSecret[i]) { ok = false; }\n"
                "}\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(keyAgreementChaiScript);
                std::cout << "Static-link scripting KeyAgreement (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting KeyAgreement (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* keyAgreementPythonScript =
                "alice = CryptoApi()\n"
                "bob = CryptoApi()\n"
                "alice.GenerateKeyAgreementKeyPair()\n"
                "bob.GenerateKeyAgreementKeyPair()\n"
                "alicePublic = alice.ExportKeyAgreementPublicKey()\n"
                "bobPublic = bob.ExportKeyAgreementPublicKey()\n"
                "aliceSecret = alice.DeriveSharedSecret(bobPublic)\n"
                "bobSecret = bob.DeriveSharedSecret(alicePublic)\n"
                "ok = (len(aliceSecret) == len(bobSecret)) and (len(aliceSecret) == alice.GetSharedSecretSize())\n"
                "for i in range(len(aliceSecret)):\n"
                "    if aliceSecret[i] != bobSecret[i]:\n"
                "        ok = False\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(keyAgreementPythonScript);
                std::cout << "Static-link scripting KeyAgreement (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting KeyAgreement (Python): FAILED exception " << ex.what() << std::endl;
            }

            const char* randomLuaScript =
                "local api = CryptoApi.new()\n"
                "local randomBytes = api:GenerateRandomBytes(32)\n"
                "ok = (#randomBytes == 32)\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(randomLuaScript);
                std::cout << "Static-link scripting Random (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Random (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* randomLuaBridgeScript =
                "local api = CryptoApi()\n"
                "local randomBytes = api:GenerateRandomBytes(32)\n"
                "ok = (#randomBytes == 32)\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(randomLuaBridgeScript);
                std::cout << "Static-link scripting Random (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Random (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(randomLuaBridgeScript);
                std::cout << "Static-link scripting Random (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Random (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* randomChaiScript =
                "var api = CryptoApi();\n"
                "var randomBytes = api.GenerateRandomBytes(32);\n"
                "global ok = (randomBytes.size() == 32);\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(randomChaiScript);
                std::cout << "Static-link scripting Random (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Random (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* randomPythonScript =
                "api = CryptoApi()\n"
                "randomBytes = api.GenerateRandomBytes(32)\n"
                "ok = (len(randomBytes) == 32)\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(randomPythonScript);
                std::cout << "Static-link scripting Random (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Random (Python): FAILED exception " << ex.what() << std::endl;
            }

            const char* pgpSignVerifyLuaScript =
                "local alice = PgpEngine.new()\n"
                "local bob = PgpEngine.new()\n"
                "alice:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-librunner-lua-pw\")\n"
                "bob:GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-librunner-lua-pw\")\n"
                "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
                "local message = \"This clear-signed message comes from LibRunner Lua.\"\n"
                "local signed = alice:ClearSignString(\"alice-librunner-lua-pw\", message)\n"
                "ok = bob:VerifyClearSignedString(signed)\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(pgpSignVerifyLuaScript);
                std::cout << "Static-link scripting PgpSignVerify (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpSignVerify (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* pgpSignVerifyLuaBridgeScript =
                "local alice = PgpEngine()\n"
                "local bob = PgpEngine()\n"
                "alice:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-librunner-luabridge-pw\")\n"
                "bob:GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-librunner-luabridge-pw\")\n"
                "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
                "local message = \"This clear-signed message comes from LibRunner LuaBridge.\"\n"
                "local signed = alice:ClearSignString(\"alice-librunner-luabridge-pw\", message)\n"
                "ok = bob:VerifyClearSignedString(signed)\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(pgpSignVerifyLuaBridgeScript);
                std::cout << "Static-link scripting PgpSignVerify (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpSignVerify (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(pgpSignVerifyLuaBridgeScript);
                std::cout << "Static-link scripting PgpSignVerify (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpSignVerify (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* pgpSignVerifyChaiScript =
                "var alice = PgpEngine();\n"
                "var bob = PgpEngine();\n"
                "alice.GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-librunner-chaiscript-pw\");\n"
                "bob.GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-librunner-chaiscript-pw\");\n"
                "bob.ImportPeerPublicKey(alice.ExportPublicKeyArmored());\n"
                "var message = \"This clear-signed message comes from LibRunner ChaiScript.\";\n"
                "var signedMessage = alice.ClearSignString(\"alice-librunner-chaiscript-pw\", message);\n"
                "global ok = bob.VerifyClearSignedString(signedMessage);\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(pgpSignVerifyChaiScript);
                std::cout << "Static-link scripting PgpSignVerify (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpSignVerify (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* pgpSignVerifyPythonScript =
                "alice = PgpEngine()\n"
                "bob = PgpEngine()\n"
                "alice.GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-librunner-python-pw\")\n"
                "bob.GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-librunner-python-pw\")\n"
                "bob.ImportPeerPublicKey(alice.ExportPublicKeyArmored())\n"
                "message = \"This clear-signed message comes from LibRunner Python.\"\n"
                "signedMessage = alice.ClearSignString(\"alice-librunner-python-pw\", message)\n"
                "ok = bob.VerifyClearSignedString(signedMessage)\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(pgpSignVerifyPythonScript);
                std::cout << "Static-link scripting PgpSignVerify (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpSignVerify (Python): FAILED exception " << ex.what() << std::endl;
            }

            const char* pgpWrapperAvailabilityLuaScript =
                "local wrapper = PgpEngineWrapper.new()\n"
                "gnupgAvailable = wrapper:IsGnuPgAvailable()\n"
                "ok = true\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(pgpWrapperAvailabilityLuaScript);
                std::cout << "Static-link scripting PgpWrapperAvailability (sol2): PASSED (GnuPG available=" << (luaEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpWrapperAvailability (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* pgpWrapperAvailabilityLuaBridgeScript =
                "local wrapper = PgpEngineWrapper()\n"
                "gnupgAvailable = wrapper:IsGnuPgAvailable()\n"
                "ok = true\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(pgpWrapperAvailabilityLuaBridgeScript);
                std::cout << "Static-link scripting PgpWrapperAvailability (LuaBridge3): PASSED (GnuPG available=" << (luaBridgeEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpWrapperAvailability (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(pgpWrapperAvailabilityLuaBridgeScript);
                std::cout << "Static-link scripting PgpWrapperAvailability (LuaBridge 2.10): PASSED (GnuPG available=" << (luaBridgeLegacyEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpWrapperAvailability (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* pgpWrapperAvailabilityChaiScript =
                "var wrapper = PgpEngineWrapper();\n"
                "global gnupgAvailable = wrapper.IsGnuPgAvailable();\n"
                "global ok = true;\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(pgpWrapperAvailabilityChaiScript);
                std::cout << "Static-link scripting PgpWrapperAvailability (ChaiScript): PASSED (GnuPG available=" << (chaiEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpWrapperAvailability (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* pgpWrapperAvailabilityPythonScript =
                "wrapper = PgpEngineWrapper()\n"
                "gnupgAvailable = wrapper.IsGnuPgAvailable()\n"
                "ok = True\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(pgpWrapperAvailabilityPythonScript);
                std::cout << "Static-link scripting PgpWrapperAvailability (Python): PASSED (GnuPG available=" << (pythonEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting PgpWrapperAvailability (Python): FAILED exception " << ex.what() << std::endl;
            }
        }

        // Certificate/CMS/Timestamp scripting via the SAME statically-linked-facade convention as
        // the CryptoApi/PgpEngine block above -- CertificateManager.new()/CmsService.new()/
        // TimestampService.new() (sol2) or CertificateManager()/CmsService()/TimestampService()
        // (the rest) construct a fresh CScriptCertificateManager/CScriptCmsService/
        // CScriptTimestampService owning its own concrete CCertificateManager/CCmsService/
        // CTimestampService BY VALUE, no DLL boundary involved. Same script bodies
        // ScriptEngineTester.cpp's own RunLuaScriptCertificateTest family already exercises
        // natively (self-signed cert + CMS sign/verify + RFC 3161 request creation), shown here
        // working from a statically-linked LibRunner build too, same as DllRunner's DLL-hosted
        // Certificate/CMS/Timestamp block above.
        {
            std::cout << std::endl;

            const char* luaScript =
                "local cert = CertificateManager.new()\n"
                "local certDer = cert:CreateSelfSignedCertificate(\"librunner-lua.example.com\", \"\", 0, 30, 1, 0, 0)\n"
                "local info = cert:GetCertificateInfoText(certDer)\n"
                "local certOk = (#certDer > 0) and (#info > 0)\n"
                "local cms = CmsService.new()\n"
                "local privateKeyPem = cert:GetLastPrivateKeyPem()\n"
                "local data = ToBytes(\"CMS test data from LibRunner Lua\")\n"
                "local cmsDer = cms:SignDetached(data, certDer, privateKeyPem, 0)\n"
                "local verifyResult = cms:VerifyDetached(data, cmsDer, ToBytes(\"\"))\n"
                "local cmsOk = (verifyResult == 0)\n"
                "local ts = TimestampService.new()\n"
                "local digest = ToBytes(\"0123456789012345678901234567890a\")\n"
                "local requestDer = ts:CreateTimestampRequest(digest, 0)\n"
                "local tsOk = (#requestDer > 0)\n"
                "ok = certOk and cmsOk and tsOk\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineSol luaEngine;
                luaEngine.RunString(luaScript);
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (sol2): " << (luaEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (sol2): FAILED exception " << ex.what() << std::endl;
            }

            const char* luaBridgeScript =
                "local cert = CertificateManager()\n"
                "local certDer = cert:CreateSelfSignedCertificate(\"librunner-luabridge.example.com\", \"\", 0, 30, 1, 0, 0)\n"
                "local info = cert:GetCertificateInfoText(certDer)\n"
                "local certOk = (#certDer > 0) and (#info > 0)\n"
                "local cms = CmsService()\n"
                "local privateKeyPem = cert:GetLastPrivateKeyPem()\n"
                "local message = \"CMS test data from LibRunner LuaBridge\"\n"
                "local data = {}\n"
                "for i = 1, #message do data[i] = string.byte(message, i) end\n"
                "local cmsDer = cms:SignDetached(data, certDer, privateKeyPem, 0)\n"
                "local verifyResult = cms:VerifyDetached(data, cmsDer, {})\n"
                "local cmsOk = (verifyResult == 0)\n"
                "local ts = TimestampService()\n"
                "local digestMsg = \"0123456789012345678901234567890a\"\n"
                "local digest = {}\n"
                "for i = 1, #digestMsg do digest[i] = string.byte(digestMsg, i) end\n"
                "local requestDer = ts:CreateTimestampRequest(digest, 0)\n"
                "local tsOk = (#requestDer > 0)\n"
                "ok = certOk and cmsOk and tsOk\n";

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridge luaBridgeEngine;
                luaBridgeEngine.RunString(luaBridgeScript);
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (LuaBridge3): " << (luaBridgeEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (LuaBridge3): FAILED exception " << ex.what() << std::endl;
            }

            try
            {
                CryptoApiNS::CLuaScriptEngineLuaBridgeLegacy luaBridgeLegacyEngine;
                luaBridgeLegacyEngine.RunString(luaBridgeScript);
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (LuaBridge 2.10): " << (luaBridgeLegacyEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (LuaBridge 2.10): FAILED exception " << ex.what() << std::endl;
            }

            const char* chaiScript =
                "var cert = CertificateManager();\n"
                "var certDer = cert.CreateSelfSignedCertificate(\"librunner-chai.example.com\", \"\", 0, 30, 1, 0, 0);\n"
                "var info = cert.GetCertificateInfoText(certDer);\n"
                "var certOk = (certDer.size() > 0) && (info.size() > 0);\n"
                "var cms = CmsService();\n"
                "var privateKeyPem = cert.GetLastPrivateKeyPem();\n"
                "var data = ToBytes(\"CMS test data from LibRunner ChaiScript\");\n"
                "var emptyBytes = ToBytes(\"\");\n"
                "var cmsDer = cms.SignDetached(data, certDer, privateKeyPem, 0);\n"
                "var verifyResult = cms.VerifyDetached(data, cmsDer, emptyBytes);\n"
                "var cmsOk = (verifyResult == 0);\n"
                "var ts = TimestampService();\n"
                "var digest = ToBytes(\"0123456789012345678901234567890a\");\n"
                "var requestDer = ts.CreateTimestampRequest(digest, 0);\n"
                "var tsOk = (requestDer.size() > 0);\n"
                "global ok = certOk && cmsOk && tsOk;\n";

            try
            {
                CryptoApiNS::CChaiScriptEngine chaiEngine;
                chaiEngine.RunString(chaiScript);
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (ChaiScript): " << (chaiEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (ChaiScript): FAILED exception " << ex.what() << std::endl;
            }

            const char* pythonScript =
                "cert = CertificateManager()\n"
                "certDer = cert.CreateSelfSignedCertificate(\"librunner-python.example.com\", \"\", 0, 30, 1, 0, 0)\n"
                "info = cert.GetCertificateInfoText(certDer)\n"
                "certOk = (len(certDer) > 0) and (len(info) > 0)\n"
                "cms = CmsService()\n"
                "privateKeyPem = cert.GetLastPrivateKeyPem()\n"
                "data = ToBytes(\"CMS test data from LibRunner Python\")\n"
                "cmsDer = cms.SignDetached(data, certDer, privateKeyPem, 0)\n"
                "verifyResult = cms.VerifyDetached(data, cmsDer, [])\n"
                "cmsOk = (verifyResult == 0)\n"
                "ts = TimestampService()\n"
                "digest = ToBytes(\"0123456789012345678901234567890a\")\n"
                "requestDer = ts.CreateTimestampRequest(digest, 0)\n"
                "tsOk = (len(requestDer) > 0)\n"
                "ok = certOk and cmsOk and tsOk\n";

            try
            {
                CryptoApiNS::CPythonScriptEngine pythonEngine;
                pythonEngine.RunString(pythonScript);
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (Python): " << (pythonEngine.GetGlobalBool("ok") ? "PASSED" : "FAILED") << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cout << "Static-link scripting Certificate/CMS/Timestamp (Python): FAILED exception " << ex.what() << std::endl;
            }
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

#if 1
        // Native Certificate/CMS/Timestamp test parity with AppBuilder/Main.cpp -- LibRunner had
        // gained script demos for these classes (see project_certificate_script_demos_and_retry_fix_done
        // memory) but never the native CCryptoApiTester tests themselves, a gap the 2026-09-26
        // ranked-list work's own general parity principle flagged. Same 23 calls, same order, as
        // AppBuilder/Main.cpp's own block.
        cryptoApiTester.RunCertificateSelfSignedTest();

        cryptoApiTester.RunCertificateDerPemRoundtripTest();

        cryptoApiTester.RunCertificatePfxImportExportTest();

        cryptoApiTester.RunCertificateCsrGenerationTest();

        cryptoApiTester.RunCertificateCsrDerPemRoundtripTest();

        cryptoApiTester.RunCertificateIssueFromRequestTest();

        cryptoApiTester.RunCertificateChainValidTest();

        cryptoApiTester.RunCertificateChainUntrustedRootTest();

        cryptoApiTester.RunCertificateChainExpiredTest();

        cryptoApiTester.RunCertificateChainRevokedTest();

        cryptoApiTester.RunCertificateCrlCheckGoodTest();

        cryptoApiTester.RunCertificateCrlCheckRevokedTest();

        cryptoApiTester.RunCertificateCrlCheckStaleTest();

        cryptoApiTester.RunCertificateCrlCheckWrongIssuerRejectionTest();

        cryptoApiTester.RunCertificateChainCrypt32CdpFetchRevokedTest();

        cryptoApiTester.RunCertificateStoreMemoryFindTest();

        cryptoApiTester.RunCertificateStoreFindByFilterTest();

        cryptoApiTester.RunCmsSignVerifyDetachedTest();

        cryptoApiTester.RunCmsTamperedDataRejectionTest();

        cryptoApiTester.RunCmsUntrustedSignerRejectionTest();

        cryptoApiTester.RunCmsSigningCertificateV2AttributeTest();

        cryptoApiTester.RunCmsVerifyDetachedSigningCertMismatchTest();

        cryptoApiTester.RunTimestampRequestResponseRoundtripTest();

        cryptoApiTester.RunTimestampVerifyTest();

        cryptoApiTester.RunTimestampTamperedDigestRejectionTest();
#endif
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
        return runCliAction(parser);
    }

    return runAllTests();
}

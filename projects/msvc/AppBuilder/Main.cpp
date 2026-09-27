#include <exception>
#include <iostream>

#include "CryptoApiTester.h"
#include "Scripts/ScriptEngineTester.h"

#include "CryptoApi.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"
#include "Cli/CommandLineParser.h"
#include "Utils/Utils.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#ifdef NO_ERROR
#undef NO_ERROR
#endif

#include <string>
#include <vector>

int runTestsViaCryptoApiTester()
{
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

#if 0
    cryptoApiTester.RunPgpKeyGenerationTest();

    cryptoApiTester.RunPgpEncryptDecryptTest();

    cryptoApiTester.RunPgpSignVerifyTest();

    cryptoApiTester.RunPgpClearSignTest();

    cryptoApiTester.RunPgpArmorTest();

    cryptoApiTester.RunPgpEncryptAndSignTest();

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
    // Closes 3 previously-zero-coverage interface methods flagged by the 2026-09-22 runner parity
    // audit (see memory project_runner_parity_audit_findings.md): IPgpEngine::GetPeerKeyId,
    // IPgpEngineWrapper::GetPeerKeyId, and both IPgpEngineWrapper::EncryptStringArmoredMultiRecipient
    // overloads. Kept in its own always-on block (independent of the surrounding #if 0 PGP-wrapper
    // block above) so these run regardless of that block's own on/off state.
    cryptoApiTester.RunPgpGetPeerKeyIdTest();

    cryptoApiTester.RunPgpWrapperGetPeerKeyIdTest();

    cryptoApiTester.RunPgpWrapperMultiRecipientEncryptStringArmoredTest();
#endif

#if 1
    // New capability (4g: real gpg's default combined "--sign --encrypt" wire format) -- kept in
    // its own always-on block, same reasoning as the parity-audit block above, so it runs
    // regardless of the surrounding #if 0 PGP block's own on/off state.
    cryptoApiTester.RunPgpEncryptAndSignTest();
#endif

#if 1
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

    return 0;
}

int runTestsViaLuaScriptEngineSol()
{
    CryptoApiNS::CScriptEngineTester scriptEngineTester;

    scriptEngineTester.RunLuaScriptHashTest();

    scriptEngineTester.RunLuaScriptEncryptDecryptTest();

    scriptEngineTester.RunLuaScriptAsymmetricTest();

    scriptEngineTester.RunLuaScriptSignatureTest();

    scriptEngineTester.RunLuaScriptKeyAgreementTest();

    scriptEngineTester.RunLuaScriptRandomTest();

    scriptEngineTester.RunLuaScriptPgpKeyGenerationTest();

    scriptEngineTester.RunLuaScriptPgpEncryptDecryptTest();

    scriptEngineTester.RunLuaScriptPgpSignVerifyTest();

    scriptEngineTester.RunLuaScriptPgpWrapperAvailabilityTest();

    scriptEngineTester.RunLuaScriptProgressCallbackTest();

    scriptEngineTester.RunLuaScriptCertificateTest();

    return 0;
}

int runTestsViaLuaScriptEngineLuaBridge()
{
    CryptoApiNS::CScriptEngineTester scriptEngineTester;

    scriptEngineTester.RunLuaBridgeScriptHashTest();

    scriptEngineTester.RunLuaBridgeScriptEncryptDecryptTest();

    scriptEngineTester.RunLuaBridgeScriptAsymmetricTest();

    scriptEngineTester.RunLuaBridgeScriptSignatureTest();

    scriptEngineTester.RunLuaBridgeScriptKeyAgreementTest();

    scriptEngineTester.RunLuaBridgeScriptRandomTest();

    scriptEngineTester.RunLuaBridgeScriptPgpKeyGenerationTest();

    scriptEngineTester.RunLuaBridgeScriptPgpEncryptDecryptTest();

    scriptEngineTester.RunLuaBridgeScriptPgpSignVerifyTest();

    scriptEngineTester.RunLuaBridgeScriptPgpWrapperAvailabilityTest();

    scriptEngineTester.RunLuaBridgeScriptProgressCallbackTest();

    scriptEngineTester.RunLuaBridgeScriptCertificateTest();

    return 0;
}

int runTestsViaLuaScriptEngineLuaBridgeLegacy()
{
    CryptoApiNS::CScriptEngineTester scriptEngineTester;

    scriptEngineTester.RunLuaBridgeLegacyScriptHashTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptEncryptDecryptTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptAsymmetricTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptSignatureTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptKeyAgreementTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptRandomTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptPgpKeyGenerationTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptPgpEncryptDecryptTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptPgpSignVerifyTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptPgpWrapperAvailabilityTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptProgressCallbackTest();

    scriptEngineTester.RunLuaBridgeLegacyScriptCertificateTest();

    return 0;
}

int runTestsViaChaiScriptEngine()
{
    CryptoApiNS::CScriptEngineTester scriptEngineTester;

    scriptEngineTester.RunChaiScriptHashTest();

    scriptEngineTester.RunChaiScriptEncryptDecryptTest();

    scriptEngineTester.RunChaiScriptAsymmetricTest();

    scriptEngineTester.RunChaiScriptSignatureTest();

    scriptEngineTester.RunChaiScriptKeyAgreementTest();

    scriptEngineTester.RunChaiScriptRandomTest();

    scriptEngineTester.RunChaiScriptPgpKeyGenerationTest();

    scriptEngineTester.RunChaiScriptPgpEncryptDecryptTest();

    scriptEngineTester.RunChaiScriptPgpSignVerifyTest();

    scriptEngineTester.RunChaiScriptPgpWrapperAvailabilityTest();

    scriptEngineTester.RunChaiScriptProgressCallbackTest();

    scriptEngineTester.RunChaiScriptCertificateTest();

    return 0;
}

int runTestsViaPythonScriptEngine()
{
    CryptoApiNS::CScriptEngineTester scriptEngineTester;

    scriptEngineTester.RunPythonScriptHashTest();

    scriptEngineTester.RunPythonScriptEncryptDecryptTest();

    scriptEngineTester.RunPythonScriptAsymmetricTest();

    scriptEngineTester.RunPythonScriptSignatureTest();

    scriptEngineTester.RunPythonScriptKeyAgreementTest();

    scriptEngineTester.RunPythonScriptRandomTest();

    scriptEngineTester.RunPythonScriptPgpKeyGenerationTest();

    scriptEngineTester.RunPythonScriptPgpEncryptDecryptTest();

    scriptEngineTester.RunPythonScriptPgpSignVerifyTest();

    scriptEngineTester.RunPythonScriptPgpWrapperAvailabilityTest();

    scriptEngineTester.RunPythonScriptProgressCallbackTest();

    scriptEngineTester.RunPythonScriptCertificateTest();

    return 0;
}

// Real Unicode command-line args (excludes argv[0], the program path), converted to UTF-8 --
// plain `main(int, char**)` argv is ANSI/OEM codepage on Windows, not UTF-8, so this uses
// GetCommandLineW + CommandLineToArgvW + WideCharToMultiByte(CP_UTF8) instead (same reasoning as
// PgpEngineWrapper.cpp's own UTF-8<->UTF-16 conversion helpers, just the reverse direction).
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

// Phase 2 actions -- a deliberately bounded, real action set (NOT 1:1 with gpg.exe's own ~200
// commands/options; see the AppRunner CLI harness plan). "hash"/"encrypt-string"/"decrypt-string"
// use CCryptoApi's own default-constructed configuration (no -algorithm selector yet). "encrypt-
// string"/"decrypt-string" are genuinely usable across two SEPARATE invocations (password-based, no
// persisted key material needed) -- "pgp-roundtrip" is a single self-contained demo (generates a
// fresh identity, encrypts to itself, decrypts, all within one process) since CPgpEngine has no
// persisted-keyring story yet (a real gap the Phase 3 audit against gpg.exe should surface, not
// paper over).
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
// pgp-roundtrip above): unlike pgp-roundtrip's single bundled call, each of these is meant to be
// invoked SEPARATELY, the way a real gpg.exe user actually works -- generate a key once, then use it
// across many later, separate invocations. All operate on CPgpEngineWrapper (shells out to real
// gpg.exe/GnuPG) using a caller-chosen -keyhome directory that PERSISTS across invocations (via the
// new SetHomeDir/LoadOwnIdentity methods), unlike CPgpEngine's own pgp-roundtrip which only ever
// exists for the lifetime of one process.
const char* pgpKeyHomeDefault = ".\\pgp-keyhome";

// Common setup every pgp-* action needs: point a fresh CPgpEngineWrapper at -keyhome (or the
// default), and confirm GnuPG is actually installed on this machine before doing anything else.
// Returns nullptr (with an error already printed) on failure -- callers check for that.
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
    const std::string cipher = parser.GetString("cipher", "");
    if (!cipher.empty() && wrapper.SetCipherPreference(cipher.c_str(), static_cast<int>(cipher.size())) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "SetCipherPreference(" << cipher << ") failed" << std::endl;
        return false;
    }
    return true;
}
// -----------------------------------------------------------------------------

int runCliActionPgpCheck(const CryptoApiNS::CCommandLineParser& parser)
{
    CryptoApiNS::CPgpEngineWrapper wrapper;
    std::string keyHome;
    keyHome = parser.GetString("keyhome", pgpKeyHomeDefault);
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

int runCliActionPgpFingerprint(const CryptoApiNS::CCommandLineParser& parser)
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

    char fingerprint[64];
    const int status = wrapper.GetKeyFingerprint(fingerprint, sizeof(fingerprint));
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "GetKeyFingerprint failed, status=" << status << std::endl;
        return 1;
    }
    std::cout << fingerprint << std::endl;
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
    // Self-encrypt (v1): the own identity is also the recipient -- true multi-party (two separate
    // -keyhome identities exchanging exported public keys) is a natural follow-up, not built now.
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

// Combined "gpg --sign --encrypt" in ONE gpg call -- real gpg's own default sign+encrypt wire
// format (signature embedded INSIDE the encrypted+compressed layer), NOT the same as running
// pgp-sign and pgp-encrypt separately (which would produce two independent messages).
int runCliActionPgpSignEncrypt(const CryptoApiNS::CCommandLineParser& parser)
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
    // Self-encrypt+self-verify (v1), same reasoning as pgp-encrypt/pgp-verify above.
    if (wrapper.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(armoredPub), armoredPubSize) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ImportPeerPublicKey(self) failed" << std::endl;
        return 1;
    }

    const std::string password = parser.GetString("password", "");
    const std::string input = parser.GetString("input", "");
    char encrypted[16384];
    int encryptedSize = 0;
    const int status = wrapper.EncryptAndSignStringArmored( password.c_str(), static_cast<int>(password.size()),
                                                            input.c_str(), static_cast<int>(input.size()),
                                                            sizeof(encrypted), encrypted, &encryptedSize);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "EncryptAndSignStringArmored failed, status=" << status << std::endl;
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

// Counterpart to pgp-sign-encrypt above -- decrypts AND requires/verifies the embedded signature.
// Fails if the input has no embedded signature at all (use pgp-decrypt for a plain encrypted-only
// message).
int runCliActionPgpDecryptVerify(const CryptoApiNS::CCommandLineParser& parser)
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
    // DecryptAndVerifyStringArmored requires ImportPeerPublicKey to have run at least once on this
    // instance (same API-level guard VerifyClearSignedString already has) -- importing our own
    // pubkey here satisfies it for the self-signed scenario this action covers.
    if (wrapper.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(armoredPub), armoredPubSize) != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "ImportPeerPublicKey(self) failed" << std::endl;
        return 1;
    }

    const std::string password = parser.GetString("password", "");
    const std::string input = parser.GetString("input", "");
    unsigned char plainBuffer[16384];
    int plainSize = 0;
    bool isSignatureValid = false;
    const int status = wrapper.DecryptAndVerifyStringArmored( password.c_str(), static_cast<int>(password.size()),
                                                              input.c_str(), static_cast<int>(input.size()),
                                                              sizeof(plainBuffer), plainBuffer, &plainSize, &isSignatureValid);
    if (status != CryptoApiNS::NO_ERROR)
    {
        std::cerr << "DecryptAndVerifyStringArmored failed, status=" << status << std::endl;
        return 1;
    }
    std::cout << std::string(reinterpret_cast<const char*>(plainBuffer), static_cast<std::size_t>(plainSize)) << std::endl;
    std::cerr << "signature: " << (isSignatureValid ? "VALID" : "INVALID") << std::endl;
    return isSignatureValid ? 0 : 7;
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
    // VerifyClearSignedString requires ImportPeerPublicKey to have run at least once on this
    // instance (an API-level guard, independent of what gpg's own keyring already contains) --
    // importing our own pubkey here satisfies it for the self-signed scenario this action covers.
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

// The exact sequence main() always ran unconditionally before the CLI existed (CCryptoApiTester's
// full suite + all 5 script engines' own demo/test suites) -- extracted here, unchanged, so it can be
// triggered explicitly via `-action run-tests` as well as by the original no-args fallback in main().
int runAllTests()
{
    std::cout << std::endl;

    std::cout << "runTestsViaCryptoApiTester()...." << std::endl;

    std::cout << std::endl;

    runTestsViaCryptoApiTester();



    std::cout << std::endl;

    std::cout << "runTestsViaLuaScriptEngineSol()...." << std::endl;

    std::cout << std::endl;

    runTestsViaLuaScriptEngineSol();



    std::cout << std::endl;

    std::cout << "runTestsViaLuaScriptEngineLuaBridge()...." << std::endl;

    std::cout << std::endl;

    runTestsViaLuaScriptEngineLuaBridge();



    std::cout << std::endl;

    std::cout << "runTestsViaLuaScriptEngineLuaBridgeLegacy()...." << std::endl;

    std::cout << std::endl;

    runTestsViaLuaScriptEngineLuaBridgeLegacy();



    std::cout << std::endl;

    std::cout << "runTestsViaChaiScriptEngine()...." << std::endl;

    std::cout << std::endl;

    runTestsViaChaiScriptEngine();



    std::cout << std::endl;

    std::cout << "runTestsViaPythonScriptEngine()...." << std::endl;

    std::cout << std::endl;

    runTestsViaPythonScriptEngine();



    std::cout << std::endl;

    return 0;
}
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
        "PGP (CPgpEngine, tek process icinde bundled demo):\n"
        "  pgp-roundtrip           [-userid ID] -password X -message TEXT\n"
        "\n"
        "PGP (CPgpEngineWrapper, gpg.exe benzeri, kalici -keyhome ile ayri invocation'lar arasi):\n"
        "  pgp-check               [-keyhome DIR]\n"
        "  pgp-gen-key             [-keyhome DIR] [-userid ID] -password X\n"
        "  pgp-list-keys           [-keyhome DIR]\n"
        "  pgp-export-key          [-keyhome DIR]\n"
        "  pgp-fingerprint         [-keyhome DIR]                       (tam 40 hex karakterlik RFC4880 fingerprint)\n"
        "  pgp-encrypt             [-keyhome DIR] [-cipher NAME] -password X -input TEXT\n"
        "  pgp-decrypt             [-keyhome DIR] -password X -input ARMORED\n"
        "  pgp-sign                [-keyhome DIR] -password X -input TEXT\n"
        "  pgp-verify              [-keyhome DIR] -input ARMORED\n"
        "  pgp-sign-encrypt        [-keyhome DIR] [-cipher NAME] -password X -input TEXT   (tek gpg cagrisinda birlesik sign+encrypt)\n"
        "  pgp-decrypt-verify      [-keyhome DIR] -password X -input ARMORED                (gomulu imzayi ister/dogrular; imzasizsa hata)\n"
        "\n"
        "-keyhome varsayilani: .\\pgp-keyhome (verilmezse). [] iceki argumanlar opsiyonel (kendi varsayilanlari var).\n"
        "-cipher (ornek: AES256, AES192, AES, 3DES) her pgp-* aksiyonuna verilebilir (--personal-cipher-preferences), sadece encrypt/encrypt-symmetric'i etkiler.\n";
    return 0;
}
// -----------------------------------------------------------------------------

// Phase 1 of the AppRunner CLI plan proved the argv-forwarding plumbing works end-to-end (AppRunner
// spawns this exe with the same args, this dispatches, AppRunner echoes the result); Phase 2 grows
// the action set above this dispatcher.
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
    if (action == "pgp-fingerprint")
    {
        return runCliActionPgpFingerprint(parser);
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
    if (action == "pgp-sign-encrypt")
    {
        return runCliActionPgpSignEncrypt(parser);
    }
    if (action == "pgp-decrypt-verify")
    {
        return runCliActionPgpDecryptVerify(parser);
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
                 "pgp-export-key, pgp-fingerprint, pgp-encrypt, pgp-decrypt, pgp-sign, pgp-verify, "
                 "pgp-sign-encrypt, pgp-decrypt-verify, run-tests, list-actions (run -action "
                 "list-actions for full usage)" << std::endl;
    return 2;
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

#include "CryptoApiTester.h"
#include "Scripts/ScriptEngineTester.h"

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

    return 0;
}

int main()
{
    //runTestsViaCryptoApiTester();

    runTestsViaLuaScriptEngineSol();

    runTestsViaLuaScriptEngineLuaBridge();

    runTestsViaLuaScriptEngineLuaBridgeLegacy();

    return 0;
}

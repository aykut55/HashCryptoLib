#ifndef CRYPTOAPI_INTERFACES_ICRYPTO_API_TESTER_H
#define CRYPTOAPI_INTERFACES_ICRYPTO_API_TESTER_H

namespace CryptoApiNS
{

// Pure-virtual mirror of every public CCryptoApiTester test method (see CryptoApiTester.h for the
// full documentation of each -- not repeated here to avoid drift). Exists so a CCryptoApiTester
// instance created inside a DLL (via CreateCryptoApiTester(), see CryptoApiFactory.h) can be used
// by a caller that only dynamically loaded that DLL (LoadLibrary/GetProcAddress, see
// DllLoader/CryptoApiDllLoader.h) instead of linking against it at compile time -- same reasoning
// as ICryptoApi. CCryptoApiTester's private runNonBlocking helper is intentionally NOT mirrored
// here (it takes a CCryptoApiTester-specific pointer-to-member-function argument that has no
// meaning across a DLL boundary, and callers never invoke it directly).
class ICryptoApiTester
{
public:
    virtual ~ICryptoApiTester();
             ICryptoApiTester();

    virtual int Run(void) = 0;

    virtual int RunEncryptDecryptFileTest(void) = 0;

    virtual int RunEncryptDecryptStringTest(void) = 0;

    virtual int RunEncryptDecryptBufferTest(void) = 0;

    virtual int RunEncryptDecryptBytesTest(void) = 0;

    virtual int RunHashFileTest(void) = 0;

    virtual int RunHashStringTest(void) = 0;

    virtual int RunHashBufferTest(void) = 0;

    virtual int RunHashBytesTest(void) = 0;

    virtual int RunMicrosoftProviderEncryptDecryptFileTest(void) = 0;

    virtual int RunMicrosoftProviderEncryptDecryptStringTest(void) = 0;

    virtual int RunMicrosoftProviderEncryptDecryptBufferTest(void) = 0;

    virtual int RunMicrosoftProviderEncryptDecryptBytesTest(void) = 0;

    virtual int RunCryptoPPProviderEncryptDecryptFileTest(void) = 0;

    virtual int RunCryptoPPProviderEncryptDecryptStringTest(void) = 0;

    virtual int RunCryptoPPProviderEncryptDecryptBufferTest(void) = 0;

    virtual int RunCryptoPPProviderEncryptDecryptBytesTest(void) = 0;

    virtual int RunBotanProviderEncryptDecryptFileTest(void) = 0;

    virtual int RunBotanProviderEncryptDecryptStringTest(void) = 0;

    virtual int RunBotanProviderEncryptDecryptBufferTest(void) = 0;

    virtual int RunBotanProviderEncryptDecryptBytesTest(void) = 0;

    virtual int RunOpenSslProviderEncryptDecryptFileTest(void) = 0;

    virtual int RunOpenSslProviderEncryptDecryptStringTest(void) = 0;

    virtual int RunOpenSslProviderEncryptDecryptBufferTest(void) = 0;

    virtual int RunOpenSslProviderEncryptDecryptBytesTest(void) = 0;

    virtual int RunLibgcryptProviderEncryptDecryptFileTest(void) = 0;

    virtual int RunLibgcryptProviderEncryptDecryptStringTest(void) = 0;

    virtual int RunLibgcryptProviderEncryptDecryptBufferTest(void) = 0;

    virtual int RunLibgcryptProviderEncryptDecryptBytesTest(void) = 0;

    virtual int RunMicrosoftProviderAsymmetricTest(void) = 0;

    virtual int RunCryptoPPProviderAsymmetricTest(void) = 0;

    virtual int RunBotanProviderAsymmetricTest(void) = 0;

    virtual int RunOpenSslProviderAsymmetricTest(void) = 0;

    virtual int RunLibgcryptProviderAsymmetricTest(void) = 0;

    virtual int RunMicrosoftProviderLegacyTest(void) = 0;

    virtual int RunCryptoPPProviderLegacyTest(void) = 0;

    virtual int RunBotanProviderLegacyTest(void) = 0;

    virtual int RunOpenSslProviderLegacyTest(void) = 0;

    virtual int RunLibgcryptProviderLegacyTest(void) = 0;

    virtual int RunLegacyAlgorithmsTest(void) = 0;

    virtual int RunAesConfigurationDemoTest(void) = 0;

    virtual int RunEncodingUtilsTest(void) = 0;

    virtual int RunPaddingUtilsTest(void) = 0;

    virtual int RunEncryptHexBase64CompositionTest(void) = 0;

    virtual int RunEncryptFileHexBase64CompositionTest(void) = 0;

    virtual int RunHashHexBase64CompositionTest(void) = 0;

    virtual int RunHashFileHexBase64CompositionTest(void) = 0;

    virtual int RunMicrosoftProviderHashTest(void) = 0;

    virtual int RunCryptoPPProviderHashTest(void) = 0;

    virtual int RunBotanProviderHashTest(void) = 0;

    virtual int RunOpenSslProviderHashTest(void) = 0;

    virtual int RunLibgcryptProviderHashTest(void) = 0;

    virtual int RunHashAlgorithmsTest(void) = 0;

    virtual int RunMicrosoftProviderSignatureTest(void) = 0;

    virtual int RunCryptoPPProviderSignatureTest(void) = 0;

    virtual int RunBotanProviderSignatureTest(void) = 0;

    virtual int RunOpenSslProviderSignatureTest(void) = 0;

    virtual int RunLibgcryptProviderSignatureTest(void) = 0;

    virtual int RunSignatureAlgorithmsTest(void) = 0;

    virtual int RunMicrosoftProviderKeyAgreementTest(void) = 0;

    virtual int RunCryptoPPProviderKeyAgreementTest(void) = 0;

    virtual int RunBotanProviderKeyAgreementTest(void) = 0;

    virtual int RunOpenSslProviderKeyAgreementTest(void) = 0;

    virtual int RunLibgcryptProviderKeyAgreementTest(void) = 0;

    virtual int RunKeyAgreementAlgorithmsTest(void) = 0;

    virtual int RunAESTests(void) = 0;

    virtual int RunSharedInstanceTest(void) = 0;

    virtual int RunRandomAlgorithmsTest(void) = 0;

    virtual int RunEncryptStringMultilingualTest(void) = 0;

    virtual int RunPrimitiveDataTest(void) = 0;

    virtual int RunPrimitiveArrayDataTest(void) = 0;

    virtual int RunVectorDataTest(void) = 0;

    virtual int RunVectorWideStringDataTest(void) = 0;

    virtual int RunProviderFactoryTest(void) = 0;

    virtual int RunProviderFactoryFileTest(void) = 0;

    virtual int RunProviderFactoryStringTest(void) = 0;

    virtual int RunProviderFactoryBufferTest(void) = 0;

    virtual int RunProviderFactoryBytesTest(void) = 0;

    virtual int RunProviderFactoryHashTest(void) = 0;

    virtual int RunProviderFactoryHashFileTest(void) = 0;

    virtual int RunProviderFactoryHashStringTest(void) = 0;

    virtual int RunProviderFactoryHashBufferTest(void) = 0;

    virtual int RunProviderFactoryHashBytesTest(void) = 0;

    virtual int RunMicrosoftProviderAllAlgorithmsTest(void) = 0;

    virtual int RunCryptoPPProviderAllAlgorithmsTest(void) = 0;

    virtual int RunBotanProviderAllAlgorithmsTest(void) = 0;

    virtual int RunOpenSslProviderAllAlgorithmsTest(void) = 0;

    virtual int RunLibgcryptProviderAllAlgorithmsTest(void) = 0;

    virtual int RunEncryptDecryptFileTestNonBlocking(void) = 0;

    virtual int RunEncryptDecryptStringTestNonBlocking(void) = 0;

    virtual int RunEncryptDecryptBufferTestNonBlocking(void) = 0;

    virtual int RunEncryptDecryptBytesTestNonBlocking(void) = 0;

    virtual int RunHashFileTestNonBlocking(void) = 0;

    virtual int RunHashStringTestNonBlocking(void) = 0;

    virtual int RunHashBufferTestNonBlocking(void) = 0;

    virtual int RunHashBytesTestNonBlocking(void) = 0;

    virtual int RunPgpKeyGenerationTest(void) = 0;

    virtual int RunPgpEncryptDecryptTest(void) = 0;

    virtual int RunPgpSignVerifyTest(void) = 0;

    virtual int RunPgpClearSignTest(void) = 0;

    virtual int RunPgpArmorTest(void) = 0;

    virtual int RunPgpAliceBobTest(void) = 0;

    virtual int RunPgpFileEncryptDecryptTest(void) = 0;

    virtual int RunPgpFileSignVerifyTest(void) = 0;

    virtual int RunPgpEccFileStreamingTest(void) = 0;

    virtual int RunPgpGnuPgInteropTest(void) = 0;

    virtual int RunPgpKeyExpirationTest(void) = 0;

    virtual int RunPgpGnuPgRevocationInteropTest(void) = 0;

    virtual int RunPgpMultiRecipientEncryptDecryptTest(void) = 0;

    virtual int RunPgpMixedRecipientEncryptDecryptTest(void) = 0;

    virtual int RunPgpMultiRecipientFileEncryptDecryptTest(void) = 0;

    virtual int RunPgpGnuPgMultiRecipientInteropTest(void) = 0;

    virtual int RunPgpGnuPgMixedAlgorithmRecipientInteropTest(void) = 0;

    virtual int RunPgpEd25519KeyGenerationTest(void) = 0;

    virtual int RunPgpEd25519EncryptDecryptTest(void) = 0;

    virtual int RunPgpEd25519SignVerifyTest(void) = 0;

    virtual int RunPgpEd25519ClearSignTest(void) = 0;

    virtual int RunPgpGnuPgEd25519InteropTest(void) = 0;

    virtual int RunPgpEd25519KeyExpirationTest(void) = 0;

    virtual int RunPgpGnuPgEd25519RevocationInteropTest(void) = 0;

    virtual int RunPgpEncryptFileCompressedZipTest(void) = 0;

    virtual int RunPgpEncryptFileCompressedZlibTest(void) = 0;

    virtual int RunPgpEncryptFileCompressedEmptyFileTest(void) = 0;

    virtual int RunPgpEncryptFileCompressedLargeFileTest(void) = 0;

    virtual int RunPgpEncryptFileCompressedCancellationTest(void) = 0;

    virtual int RunPgpEncryptFileCompressedCorruptionTest(void) = 0;

    virtual int RunPgpGnuPgBzip2InteropTest(void) = 0;

    virtual int RunPgpGnuPgBzip2DecryptBufferInteropTest(void) = 0;

    virtual int RunPgpGnuPgPartialBodyLengthInteropTest(void) = 0;

    virtual int RunPgpInspectionEncryptedMessageTest(void) = 0;

    virtual int RunPgpInspectionMultiRecipientTest(void) = 0;

    virtual int RunPgpInspectionSignatureTest(void) = 0;

    virtual int RunPgpGnuPgInspectionInteropTest(void) = 0;

    virtual int RunPgpWrapperAvailabilityTest(void) = 0;

    virtual int RunPgpWrapperKeyGenerationTest(void) = 0;

    virtual int RunPgpWrapperEncryptDecryptTest(void) = 0;

    virtual int RunPgpWrapperSignVerifyTest(void) = 0;

    virtual int RunPgpWrapperClearSignTest(void) = 0;

    virtual int RunPgpWrapperAliceBobTest(void) = 0;

    virtual int RunPgpWrapperFileEncryptDecryptTest(void) = 0;

    virtual int RunPgpWrapperFileSignVerifyTest(void) = 0;

    virtual int RunPgpWrapperKeyExpirationTest(void) = 0;

    virtual int RunPgpWrapperKeyRevocationTest(void) = 0;

    virtual int RunPgpWrapperMultiRecipientEncryptTest(void) = 0;

    virtual int RunPgpWrapperEccKeyGenerationTest(void) = 0;

    virtual int RunPgpWrapperSymmetricEncryptDecryptTest(void) = 0;

    virtual int RunPgpWrapperKeyringListDeleteTest(void) = 0;

    virtual int RunPgpWrapperCompressionAlgorithmTest(void) = 0;

    virtual int RunPgpWrapperInspectionEncryptedMessageTest(void) = 0;

    virtual int RunPgpWrapperInspectionMultiRecipientTest(void) = 0;

    virtual int RunPgpWrapperInspectionSymmetricTest(void) = 0;

    virtual int RunPgpWrapperInspectionSignatureTest(void) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

#include "CryptoApiTester.h"

int main()
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
#endif

#if 0
    cryptoApiTester.RunMicrosoftProviderAsymmetricTest();

    cryptoApiTester.RunCryptoPPProviderAsymmetricTest();

    cryptoApiTester.RunBotanProviderAsymmetricTest();

    cryptoApiTester.RunOpenSslProviderAsymmetricTest();
#endif

#if 0
    cryptoApiTester.RunMicrosoftProviderLegacyTest();

    cryptoApiTester.RunCryptoPPProviderLegacyTest();

    cryptoApiTester.RunBotanProviderLegacyTest();

    cryptoApiTester.RunOpenSslProviderLegacyTest();
#endif

#if 0
    cryptoApiTester.RunLegacyAlgorithmsTest();
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
#endif

#if 0
    cryptoApiTester.RunEncodingUtilsTest();

    //cryptoApiTester.RunAesConfigurationDemoTest();

    cryptoApiTester.RunPaddingUtilsTest();
#endif

#if 0
    cryptoApiTester.RunEncryptHexBase64CompositionTest();

    cryptoApiTester.RunEncryptFileHexBase64CompositionTest();
#endif

#if 1
    cryptoApiTester.RunMicrosoftProviderHashTest();

    cryptoApiTester.RunCryptoPPProviderHashTest();

    cryptoApiTester.RunBotanProviderHashTest();

    cryptoApiTester.RunOpenSslProviderHashTest();
#endif

#if 1
    cryptoApiTester.RunHashAlgorithmsTest();
#endif

#if 1
    cryptoApiTester.RunHashFileTest();

    cryptoApiTester.RunHashStringTest();

    cryptoApiTester.RunHashBufferTest();

    cryptoApiTester.RunHashBytesTest();
#endif

#if 1
    cryptoApiTester.RunProviderFactoryHashTest();

    cryptoApiTester.RunProviderFactoryHashFileTest();

    cryptoApiTester.RunProviderFactoryHashStringTest();

    cryptoApiTester.RunProviderFactoryHashBufferTest();

    cryptoApiTester.RunProviderFactoryHashBytesTest();
#endif

#if 1
    cryptoApiTester.RunHashHexBase64CompositionTest();

    cryptoApiTester.RunHashFileHexBase64CompositionTest();
#endif

#if 1
    cryptoApiTester.RunHashFileTestNonBlocking();

    cryptoApiTester.RunHashStringTestNonBlocking();

    cryptoApiTester.RunHashBufferTestNonBlocking();

    cryptoApiTester.RunHashBytesTestNonBlocking();
#endif

    return 0;
}

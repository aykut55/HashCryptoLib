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
    cryptoApiTester.RunEncryptStringMultilingualTest();

    cryptoApiTester.RunPrimitiveDataTest();

    cryptoApiTester.RunPrimitiveArrayDataTest();

    cryptoApiTester.RunVectorDataTest();

    cryptoApiTester.RunVectorWideStringDataTest();
#endif
/*
    cryptoApiTester.RunProviderFactoryTest();

    cryptoApiTester.RunProviderFactoryFileTest();

    cryptoApiTester.RunProviderFactoryStringTest();

    cryptoApiTester.RunProviderFactoryBufferTest();

    cryptoApiTester.RunProviderFactoryBytesTest();
*/
#if 0
    cryptoApiTester.RunEncryptDecryptFileTestNonBlocking();

    cryptoApiTester.RunEncryptDecryptStringTestNonBlocking();

    cryptoApiTester.RunEncryptDecryptBufferTestNonBlocking();

    cryptoApiTester.RunEncryptDecryptBytesTestNonBlocking();
#endif

    cryptoApiTester.RunMicrosoftProviderAllAlgorithmsTest();

    cryptoApiTester.RunCryptoPPProviderAllAlgorithmsTest();

    cryptoApiTester.RunBotanProviderAllAlgorithmsTest();

    cryptoApiTester.RunOpenSslProviderAllAlgorithmsTest();

    return 0;
}

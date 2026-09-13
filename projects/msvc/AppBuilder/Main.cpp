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

    cryptoApiTester.RunEncryptStringMultilingualTest();

    cryptoApiTester.RunPrimitiveDataTest();

    cryptoApiTester.RunPrimitiveArrayDataTest();

    cryptoApiTester.RunVectorDataTest();

    cryptoApiTester.RunVectorWideStringDataTest();

#if 0
    cryptoApiTester.RunEncryptDecryptFileTestNonBlocking();

    cryptoApiTester.RunEncryptDecryptStringTestNonBlocking();

    cryptoApiTester.RunEncryptDecryptBufferTestNonBlocking();

    cryptoApiTester.RunEncryptDecryptBytesTestNonBlocking();
#endif

    return 0;
}

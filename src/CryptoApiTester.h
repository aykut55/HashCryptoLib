#ifndef CRYPTOAPI_CRYPTO_API_TESTER_H
#define CRYPTOAPI_CRYPTO_API_TESTER_H

namespace CryptoApiNS
{

class CCryptoApiTester
{
public:
    virtual ~CCryptoApiTester();
             CCryptoApiTester();

    int Run(void);

    int RunEncryptDecryptFileTest(void);

    int RunEncryptDecryptStringTest(void);

    int RunEncryptDecryptBufferTest(void);

    int RunEncryptDecryptBytesTest(void);

    // Round-trips EncryptString/DecryptString over English, Turkish and Japanese UTF-8 text to
    // confirm the API treats input as opaque UTF-8 bytes regardless of script/encoding width.
    int RunEncryptStringMultilingualTest(void);

    // Round-trips scalar char/short/int/long/float/double values (including zero, min/max,
    // negative, NaN and infinity) through EncryptBuffer/DecryptBuffer, byte-exact.
    int RunPrimitiveDataTest(void);

    // Same as RunPrimitiveDataTest but for whole arrays of each primitive type.
    int RunPrimitiveArrayDataTest(void);

    // Round-trips data held in std::vector containers: a vector<std::string> (each element
    // encrypted independently via EncryptString/DecryptString) and vector<short>/vector<double>
    // (each encrypted as one contiguous buffer via EncryptBuffer/DecryptBuffer).
    int RunVectorDataTest(void);

    // Round-trips a std::vector<std::wstring> by converting each element to UTF-8 before
    // EncryptString and back to std::wstring after DecryptString (CCryptoApi's string API is
    // UTF-8 only; wide strings are not passed to it directly).
    int RunVectorWideStringDataTest(void);

    // Demonstrates that CCryptoApi's blocking calls can be driven from a background thread the
    // caller owns; CCryptoApi itself stays synchronous by design (see Rules.md/Plan.md ABI notes).
    int RunEncryptDecryptFileTestNonBlocking(void);

    int RunEncryptDecryptStringTestNonBlocking(void);

    int RunEncryptDecryptBufferTestNonBlocking(void);

    int RunEncryptDecryptBytesTestNonBlocking(void);

protected:

private:

    int runNonBlocking(const char* testName, int (CCryptoApiTester::*testMethod)(void));

};

} // namespace CryptoApiNS

#endif

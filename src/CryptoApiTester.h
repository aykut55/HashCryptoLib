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

    // Variants of RunEncryptDecryptFileTest/StringTest/BufferTest/BytesTest that construct
    // CCryptoApi via CCryptoApi(const ProviderKind, const AeadAlgorithm) instead of the no-arg
    // constructor (which defaults to PROVIDER_MICROSOFT/AEAD_AES_256_GCM), so each one proves the
    // constructor-selected provider/algorithm is actually threaded through CCryptoApi's password
    // KDF + chunked encrypt/decrypt path end to end, not just the raw Factory/IAeadCipher path
    // RunProviderFactoryTest already covers. One full, independent method per provider/type pair
    // (no shared helper) so a failure names its own provider and payload shape directly.
    int RunMicrosoftProviderEncryptDecryptFileTest(void);

    int RunMicrosoftProviderEncryptDecryptStringTest(void);

    int RunMicrosoftProviderEncryptDecryptBufferTest(void);

    int RunMicrosoftProviderEncryptDecryptBytesTest(void);

    int RunCryptoPPProviderEncryptDecryptFileTest(void);

    int RunCryptoPPProviderEncryptDecryptStringTest(void);

    int RunCryptoPPProviderEncryptDecryptBufferTest(void);

    int RunCryptoPPProviderEncryptDecryptBytesTest(void);

    int RunBotanProviderEncryptDecryptFileTest(void);

    int RunBotanProviderEncryptDecryptStringTest(void);

    int RunBotanProviderEncryptDecryptBufferTest(void);

    int RunBotanProviderEncryptDecryptBytesTest(void);

    int RunOpenSslProviderEncryptDecryptFileTest(void);

    int RunOpenSslProviderEncryptDecryptStringTest(void);

    int RunOpenSslProviderEncryptDecryptBufferTest(void);

    int RunOpenSslProviderEncryptDecryptBytesTest(void);

    // Exercises CCryptoApi's RSA surface (GenerateAsymmetricKeyPair/EncryptWithPublicKey/
    // DecryptWithPrivateKey/GetMaxAsymmetricPlaintextSize/GetAsymmetricCiphertextSize) via the
    // 3-argument constructor, one full independent method per provider (no shared helper).
    int RunMicrosoftProviderAsymmetricTest(void);

    int RunCryptoPPProviderAsymmetricTest(void);

    int RunBotanProviderAsymmetricTest(void);

    int RunOpenSslProviderAsymmetricTest(void);

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

    // Exercises the provider/algorithm Factory pattern (CreateProviderFactory) directly: for each
    // ProviderKind, requests a factory, uses it to construct an IAeadCipher/ILegacyCipher for one
    // algorithm known to be supported and one known to be unsupported by that specific provider,
    // and round-trips data purely through the abstract interfaces the factory returns.
    int RunProviderFactoryTest(void);

    // File-based analogue of RunEncryptDecryptFileTest, but driven entirely by the Factory
    // pattern instead of CCryptoApi's fixed CMicrosoftProvider: for each ProviderKind, writes an
    // input file, encrypts it to disk via IAeadCipher::EncryptChunked (with progress reporting,
    // just like EncryptFile), decrypts it back from disk via DecryptChunked with a second cipher
    // instance from the same factory, and compares bytes.
    int RunProviderFactoryFileTest(void);

    // In-memory analogues of RunEncryptDecryptStringTest/BufferTest/BytesTest, driven by the
    // Factory pattern: for each ProviderKind, round-trips the same payload shape (text, binary
    // buffer, raw bytes) purely through a factory-selected IAeadCipher (AES-256-GCM). Just like
    // CCryptoApi's own EncryptBuffer/EncryptBytes (both thin wrappers over the same private
    // helper), the Buffer and Bytes variants here share one internal round-trip routine too.
    int RunProviderFactoryStringTest(void);

    int RunProviderFactoryBufferTest(void);

    int RunProviderFactoryBytesTest(void);

    // Selects PROVIDER_MICROSOFT via the Factory and exercises every AeadAlgorithm/
    // LegacySymmetricAlgorithm/AsymmetricAlgorithm value the enums define: algorithms Microsoft/
    // CNG actually supports get a full round-trip (SetKey/Encrypt/Decrypt for symmetric,
    // GenerateKeyPair/Encrypt/Decrypt for RSA), the rest are verified as correctly rejected by
    // SupportsAeadAlgorithm/SupportsLegacyAlgorithm/SupportsAsymmetricAlgorithm. Nothing here is
    // hardcoded to "GCM only" -- whatever CreateProviderFactory(PROVIDER_MICROSOFT) reports as
    // supported gets tested.
    int RunMicrosoftProviderAllAlgorithmsTest(void);

    // Same as RunMicrosoftProviderAllAlgorithmsTest, but selecting PROVIDER_CRYPTOPP instead.
    int RunCryptoPPProviderAllAlgorithmsTest(void);

    // Same as RunMicrosoftProviderAllAlgorithmsTest, but selecting PROVIDER_BOTAN instead.
    int RunBotanProviderAllAlgorithmsTest(void);

    // Same as RunMicrosoftProviderAllAlgorithmsTest, but selecting PROVIDER_OPENSSL instead.
    int RunOpenSslProviderAllAlgorithmsTest(void);

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

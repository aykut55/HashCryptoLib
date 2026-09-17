#include "CryptoApiTester.h"

#include "CryptoApi.h"
#include "Definitions/Definitions.h"
#include "Pgp/PgpEngine.h"
#include "Providers/CryptoProviderRegistry.h"
#include "Utils/Utils.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif

#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

namespace CryptoApiNS
{

namespace
{

bool WriteTesterFile(const char* path, const std::vector<unsigned char>& data)
{
    std::ofstream fileStream(path, std::ios::binary);
    if (!fileStream)
    {
        return false;
    }

    if (!data.empty())
    {
        fileStream.write(reinterpret_cast<const char*>(&data[0]), static_cast<std::streamsize>(data.size()));
    }

    return static_cast<bool>(fileStream);
}
// -----------------------------------------------------------------------------

bool ReadTesterFile(const char* path, std::vector<unsigned char>& data)
{
    std::ifstream fileStream(path, std::ios::binary | std::ios::ate);
    if (!fileStream)
    {
        return false;
    }

    const std::streamsize fileSize = fileStream.tellg();
    fileStream.seekg(0);
    data.resize(static_cast<std::size_t>(fileSize));
    if (fileSize > 0)
    {
        fileStream.read(reinterpret_cast<char*>(&data[0]), fileSize);
    }

    return static_cast<bool>(fileStream) || fileStream.eof();
}
// -----------------------------------------------------------------------------

bool __cdecl PrintFileProgress(const unsigned long long currentByte, const unsigned long long totalByte,
                               const double percentage, void* userData)
{
    (void)userData;
    const std::string totalByteText = std::to_string(totalByte);
    std::cout << "  progress: " << std::setw(static_cast<int>(totalByteText.size())) << currentByte
               << " / " << totalByteText << " bytes ("
               << std::fixed << std::setprecision(2) << std::setw(6) << percentage << "%)" << std::endl;
    return true;
}
// -----------------------------------------------------------------------------

bool __cdecl CancelAfterThirdChunk(const unsigned long long currentByte, const unsigned long long totalByte,
                                   const double percentage, void* userData)
{
    (void)currentByte;
    (void)totalByte;
    (void)percentage;
    int* callCount = static_cast<int*>(userData);
    ++(*callCount);
    return *callCount < 3;
}
// -----------------------------------------------------------------------------

template <typename T>
bool RoundTripBytes(CCryptoApi& cryptoApi, const char* password, int passwordSize,
                    const T* input, std::size_t elementCount, T* output)
{
    const unsigned char* inputBuffer = reinterpret_cast<const unsigned char*>(input);
    const int inputSize = static_cast<int>(sizeof(T) * elementCount);

    int requiredEncryptSize = 0;
    if (cryptoApi.EncryptBuffer(password, passwordSize, inputBuffer, inputSize,
                                0, nullptr, &requiredEncryptSize, nullptr, nullptr) != BUFFER_TOO_SMALL)
    {
        return false;
    }

    std::vector<unsigned char> encryptedData(requiredEncryptSize);
    int encryptedSize = 0;
    if (cryptoApi.EncryptBuffer(password, passwordSize, inputBuffer, inputSize,
                                requiredEncryptSize, &encryptedData[0], &encryptedSize,
                                nullptr, nullptr) != NO_ERROR)
    {
        return false;
    }

    int requiredDecryptSize = 0;
    if (cryptoApi.DecryptBuffer(password, passwordSize, &encryptedData[0], encryptedSize,
                                0, nullptr, &requiredDecryptSize, nullptr, nullptr) != BUFFER_TOO_SMALL ||
        requiredDecryptSize != inputSize)
    {
        return false;
    }

    unsigned char* outputBuffer = reinterpret_cast<unsigned char*>(output);
    int outputSize = 0;
    if (cryptoApi.DecryptBuffer(password, passwordSize, &encryptedData[0], encryptedSize,
                                requiredDecryptSize, outputBuffer, &outputSize,
                                nullptr, nullptr) != NO_ERROR ||
        outputSize != inputSize)
    {
        return false;
    }

    return std::memcmp(input, output, static_cast<std::size_t>(inputSize)) == 0;
}
// -----------------------------------------------------------------------------

bool EncryptDecryptStringRoundTrip(CCryptoApi& cryptoApi, const char* password, int passwordSize,
                                   const char* text, int textSize, std::string& outText)
{
    int requiredEncryptSize = 0;
    int status = cryptoApi.EncryptString(password, passwordSize, text, textSize,
                                         0, nullptr, &requiredEncryptSize, nullptr, nullptr);
    if (status != BUFFER_TOO_SMALL)
    {
        return false;
    }

    std::vector<unsigned char> encryptedData(requiredEncryptSize);
    int encryptedSize = 0;
    status = cryptoApi.EncryptString(password, passwordSize, text, textSize,
                                     requiredEncryptSize,
                                     encryptedData.empty() ? nullptr : &encryptedData[0], &encryptedSize,
                                     nullptr, nullptr);
    if (status != NO_ERROR)
    {
        return false;
    }

    int requiredDecryptSize = 0;
    status = cryptoApi.DecryptString(password, passwordSize, &encryptedData[0], encryptedSize,
                                     0, nullptr, &requiredDecryptSize, nullptr, nullptr);
    if (status == NO_ERROR && requiredDecryptSize == 0)
    {
        // Empty plaintext: capacity 0 already sufficed, so the query call above performed the
        // (trivial) decrypt itself instead of returning BUFFER_TOO_SMALL.
        outText.clear();
        return true;
    }

    if (status != BUFFER_TOO_SMALL)
    {
        return false;
    }

    std::vector<char> decryptedText(requiredDecryptSize);
    int decryptedSize = 0;
    status = cryptoApi.DecryptString(password, passwordSize, &encryptedData[0], encryptedSize,
                                     requiredDecryptSize,
                                     decryptedText.empty() ? nullptr : &decryptedText[0], &decryptedSize,
                                     nullptr, nullptr);
    if (status != NO_ERROR)
    {
        return false;
    }

    outText.assign(decryptedText.empty() ? "" : &decryptedText[0], static_cast<std::size_t>(decryptedSize));
    return true;
}
// -----------------------------------------------------------------------------

bool ConvertWideToUtf8(const std::wstring& wideText, std::string& utf8Text)
{
    if (wideText.empty())
    {
        utf8Text.clear();
        return true;
    }

    const int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wideText.c_str(), static_cast<int>(wideText.size()),
                                              nullptr, 0, nullptr, nullptr);
    if (utf8Size <= 0)
    {
        return false;
    }

    utf8Text.resize(static_cast<std::size_t>(utf8Size));
    return WideCharToMultiByte(CP_UTF8, 0, wideText.c_str(), static_cast<int>(wideText.size()),
                               &utf8Text[0], utf8Size, nullptr, nullptr) > 0;
}
// -----------------------------------------------------------------------------

bool ConvertUtf8ToWide(const char* utf8Text, int utf8Size, std::wstring& wideText)
{
    if (utf8Size == 0)
    {
        wideText.clear();
        return true;
    }

    const int wideSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Text, utf8Size, nullptr, 0);
    if (wideSize <= 0)
    {
        return false;
    }

    wideText.resize(static_cast<std::size_t>(wideSize));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Text, utf8Size, &wideText[0], wideSize) > 0;
}
// -----------------------------------------------------------------------------

bool RoundTripAeadViaFactory(const char* testName, ICryptoProviderFactory& factory, AeadAlgorithm algorithm,
                             const char* providerName, const char* algorithmName, bool expectSupported)
{
    const bool supported = factory.SupportsAeadAlgorithm(algorithm);
    if (supported != expectSupported)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] SupportsAeadAlgorithm=" << supported << " expected=" << expectSupported << std::endl;
        return false;
    }

    if (!expectSupported)
    {
        std::cout << testName << ": PASSED [" << providerName << "/" << algorithmName
                  << "] correctly unsupported" << std::endl;
        return true;
    }

    std::unique_ptr<IAeadCipher> cipher = factory.CreateAeadCipher(algorithm);
    if (!cipher)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] CreateAeadCipher returned null" << std::endl;
        return false;
    }

    const unsigned int keySize = cipher->GetKeySize();
    const unsigned int nonceSize = cipher->GetNonceSize();
    const unsigned int tagSize = cipher->GetTagSize();

    std::vector<unsigned char> key(keySize), nonce(nonceSize > 0 ? nonceSize : 1), tag(tagSize);
    for (unsigned int index = 0; index < keySize; ++index) key[index] = static_cast<unsigned char>(index * 7 + 1);
    for (unsigned int index = 0; index < nonceSize; ++index) nonce[index] = static_cast<unsigned char>(index * 3 + 2);

    if (!cipher->SetKey(key.data(), keySize))
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] SetKey" << std::endl;
        return false;
    }

    const char* plaintext = "provider factory round trip payload";
    const std::size_t len = std::strlen(plaintext);
    std::vector<unsigned char> ciphertext(len), decrypted(len);

    if (!cipher->Encrypt(nonceSize > 0 ? nonce.data() : nullptr, nonceSize,
                         reinterpret_cast<const unsigned char*>(plaintext), static_cast<unsigned int>(len),
                         ciphertext.data(), tag.data(), tagSize) ||
        !cipher->Decrypt(nonceSize > 0 ? nonce.data() : nullptr, nonceSize,
                         ciphertext.data(), static_cast<unsigned int>(len),
                         tag.data(), tagSize, decrypted.data()) ||
        std::memcmp(plaintext, decrypted.data(), len) != 0)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] round-trip mismatch" << std::endl;
        return false;
    }

    std::cout << testName << ": PASSED [" << providerName << "/" << algorithmName
              << "] round-trip via factory" << std::endl;
    return true;
}
// -----------------------------------------------------------------------------

bool RoundTripLegacyViaFactory(const char* testName, ICryptoProviderFactory& factory, LegacySymmetricAlgorithm algorithm,
                               const char* providerName, const char* algorithmName, bool expectSupported)
{
    const bool supported = factory.SupportsLegacyAlgorithm(algorithm);
    if (supported != expectSupported)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] SupportsLegacyAlgorithm=" << supported << " expected=" << expectSupported << std::endl;
        return false;
    }

    if (!expectSupported)
    {
        std::cout << testName << ": PASSED [" << providerName << "/" << algorithmName
                  << "] correctly unsupported" << std::endl;
        return true;
    }

    std::unique_ptr<ILegacyCipher> cipher = factory.CreateLegacyCipher(algorithm);
    if (!cipher)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] CreateLegacyCipher returned null" << std::endl;
        return false;
    }

    const unsigned int keySize = cipher->GetKeySize();
    const unsigned int ivSize = cipher->GetIvSize();

    std::vector<unsigned char> key(keySize);
    std::vector<unsigned char> iv(ivSize > 0 ? ivSize : 1);
    for (unsigned int index = 0; index < keySize; ++index) key[index] = static_cast<unsigned char>(index * 5 + 3);
    for (unsigned int index = 0; index < ivSize; ++index) iv[index] = static_cast<unsigned char>(index * 11 + 4);

    if (!cipher->SetKey(key.data(), keySize))
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] SetKey" << std::endl;
        return false;
    }

    const char* plaintext = "provider factory legacy round trip payload spanning blocks";
    const unsigned int len = static_cast<unsigned int>(std::strlen(plaintext));

    unsigned int requiredCt = 0;
    cipher->Encrypt(ivSize > 0 ? iv.data() : nullptr, ivSize,
                    reinterpret_cast<const unsigned char*>(plaintext), len, nullptr, 0, &requiredCt);

    std::vector<unsigned char> ciphertext(requiredCt);
    unsigned int ctSize = 0;
    if (!cipher->Encrypt(ivSize > 0 ? iv.data() : nullptr, ivSize,
                         reinterpret_cast<const unsigned char*>(plaintext), len,
                         ciphertext.data(), requiredCt, &ctSize))
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] Encrypt" << std::endl;
        return false;
    }

    // Stream ciphers (e.g. RC4) keep their keystream position on the underlying key handle, so
    // Encrypt() advances it; re-keying with the same bytes before Decrypt() resets the stream
    // back to position 0. Harmless no-op for block ciphers (CBC/ECB/CFB).
    if (!cipher->SetKey(key.data(), keySize))
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] SetKey (pre-decrypt reset)" << std::endl;
        return false;
    }

    unsigned int requiredPt = 0;
    cipher->Decrypt(ivSize > 0 ? iv.data() : nullptr, ivSize, ciphertext.data(), ctSize, nullptr, 0, &requiredPt);

    std::vector<unsigned char> decrypted(requiredPt);
    unsigned int ptSize = 0;
    if (!cipher->Decrypt(ivSize > 0 ? iv.data() : nullptr, ivSize, ciphertext.data(), ctSize,
                         decrypted.data(), requiredPt, &ptSize) ||
        ptSize != len || std::memcmp(plaintext, decrypted.data(), len) != 0)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] Decrypt/mismatch" << std::endl;
        return false;
    }

    std::cout << testName << ": PASSED [" << providerName << "/" << algorithmName
              << "] round-trip via factory" << std::endl;
    return true;
}
// -----------------------------------------------------------------------------

bool RoundTripAsymmetricViaFactory(const char* testName, ICryptoProviderFactory& factory, AsymmetricAlgorithm algorithm,
                                   const char* providerName, const char* algorithmName, bool expectSupported)
{
    const bool supported = factory.SupportsAsymmetricAlgorithm(algorithm);
    if (supported != expectSupported)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] SupportsAsymmetricAlgorithm=" << supported << " expected=" << expectSupported << std::endl;
        return false;
    }

    if (!expectSupported)
    {
        std::cout << testName << ": PASSED [" << providerName << "/" << algorithmName
                  << "] correctly unsupported" << std::endl;
        return true;
    }

    std::unique_ptr<IAsymmetricCipher> cipher = factory.CreateAsymmetricCipher(algorithm);
    if (!cipher)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] CreateAsymmetricCipher returned null" << std::endl;
        return false;
    }

    if (!cipher->GenerateKeyPair())
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] GenerateKeyPair" << std::endl;
        return false;
    }

    const unsigned int maxPlaintextSize = cipher->GetMaxPlaintextSize();
    const unsigned int ciphertextSize = cipher->GetCiphertextSize();

    const char* plaintext = "provider factory asymmetric round trip payload";
    const unsigned int len = static_cast<unsigned int>(std::strlen(plaintext));
    if (len > maxPlaintextSize)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] plaintext (" << len << " bytes) exceeds max (" << maxPlaintextSize << " bytes)" << std::endl;
        return false;
    }

    std::vector<unsigned char> ciphertext(ciphertextSize);
    unsigned int actualCiphertextSize = 0;
    if (!cipher->Encrypt(reinterpret_cast<const unsigned char*>(plaintext), len,
                        ciphertext.data(), ciphertextSize, &actualCiphertextSize))
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] Encrypt" << std::endl;
        return false;
    }

    unsigned int requiredPlaintextSize = 0;
    cipher->Decrypt(ciphertext.data(), actualCiphertextSize, nullptr, 0, &requiredPlaintextSize);

    std::vector<unsigned char> decrypted(requiredPlaintextSize);
    unsigned int decryptedSize = 0;
    if (!cipher->Decrypt(ciphertext.data(), actualCiphertextSize, decrypted.data(), requiredPlaintextSize, &decryptedSize) ||
        decryptedSize != len || std::memcmp(plaintext, decrypted.data(), len) != 0)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] Decrypt/mismatch" << std::endl;
        return false;
    }

    std::cout << testName << ": PASSED [" << providerName << "/" << algorithmName
              << "] round-trip via factory (maxPlaintext=" << maxPlaintextSize << " ciphertext=" << actualCiphertextSize << ")" << std::endl;
    return true;
}
// -----------------------------------------------------------------------------

bool RoundTripHashViaFactory(const char* testName, ICryptoProviderFactory& factory, HashAlgorithm algorithm,
                             const char* providerName, const char* algorithmName, bool expectSupported)
{
    const bool supported = factory.SupportsHashAlgorithm(algorithm);
    if (supported != expectSupported)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] SupportsHashAlgorithm=" << supported << " expected=" << expectSupported << std::endl;
        return false;
    }

    if (!expectSupported)
    {
        std::cout << testName << ": PASSED [" << providerName << "/" << algorithmName
                  << "] correctly unsupported" << std::endl;
        return true;
    }

    std::unique_ptr<IHashService> hashService = factory.CreateHashService(algorithm);
    if (!hashService)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] CreateHashService returned null" << std::endl;
        return false;
    }

    const unsigned int hashSize = hashService->GetHashSize();
    const char* plaintext = "provider factory hash round trip payload spanning more than one chunk of data";
    const unsigned int len = static_cast<unsigned int>(std::strlen(plaintext));

    std::vector<unsigned char> oneShotDigest(hashSize);
    if (!hashService->ComputeHash(reinterpret_cast<const unsigned char*>(plaintext), len, oneShotDigest.data(), hashSize))
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] ComputeHash (one-shot)" << std::endl;
        return false;
    }

    // Same content split across two Update() calls must produce the identical digest as the
    // one-shot ComputeHash above -- proves the incremental Init/Update/Final path (what
    // CCryptoApi::ComputeHashFile relies on for chunked file reads) agrees with the convenience
    // one-shot path, not just that each path is internally consistent with itself.
    const unsigned int splitPoint = len / 2;
    std::vector<unsigned char> incrementalDigest(hashSize);
    if (!hashService->Init() ||
        !hashService->Update(reinterpret_cast<const unsigned char*>(plaintext), splitPoint) ||
        !hashService->Update(reinterpret_cast<const unsigned char*>(plaintext) + splitPoint, len - splitPoint) ||
        !hashService->Final(incrementalDigest.data(), hashSize) ||
        incrementalDigest != oneShotDigest)
    {
        std::cout << testName << ": FAILED [" << providerName << "/" << algorithmName
                  << "] Init/Update/Final mismatch vs one-shot ComputeHash" << std::endl;
        return false;
    }

    std::cout << testName << ": PASSED [" << providerName << "/" << algorithmName
              << "] one-shot and incremental digests agree via factory (" << hashSize << " bytes)" << std::endl;
    return true;
}
// -----------------------------------------------------------------------------

const char* AeadAlgorithmName(AeadAlgorithm algorithm)
{
    switch (algorithm)
    {
        case AEAD_AES_128_GCM:        return "AES-128-GCM";
        case AEAD_AES_192_GCM:        return "AES-192-GCM";
        case AEAD_AES_256_GCM:        return "AES-256-GCM";
        case AEAD_AES_128_CCM:        return "AES-128-CCM";
        case AEAD_AES_192_CCM:        return "AES-192-CCM";
        case AEAD_AES_256_CCM:        return "AES-256-CCM";
        case AEAD_AES_128_EAX:        return "AES-128-EAX";
        case AEAD_AES_192_EAX:        return "AES-192-EAX";
        case AEAD_AES_256_EAX:        return "AES-256-EAX";
        case AEAD_AES_128_SIV:        return "AES-128-SIV";
        case AEAD_AES_256_SIV:        return "AES-256-SIV";
        case AEAD_AES_128_GCM_SIV:    return "AES-128-GCM-SIV";
        case AEAD_AES_256_GCM_SIV:    return "AES-256-GCM-SIV";
        case AEAD_CHACHA20_POLY1305:  return "ChaCha20-Poly1305";
        case AEAD_TWOFISH_GCM:        return "Twofish-GCM";
        case AEAD_SERPENT_GCM:        return "Serpent-GCM";
        case AEAD_CAMELLIA_GCM:       return "Camellia-GCM";
        default:                      return "?";
    }
}
// -----------------------------------------------------------------------------

const char* LegacyAlgorithmName(LegacySymmetricAlgorithm algorithm)
{
    switch (algorithm)
    {
        case LEGACY_AES_128_CBC: return "AES-128-CBC";
        case LEGACY_AES_192_CBC: return "AES-192-CBC";
        case LEGACY_AES_256_CBC: return "AES-256-CBC";
        case LEGACY_AES_128_CTR: return "AES-128-CTR";
        case LEGACY_AES_192_CTR: return "AES-192-CTR";
        case LEGACY_AES_256_CTR: return "AES-256-CTR";
        case LEGACY_AES_128_CFB: return "AES-128-CFB";
        case LEGACY_AES_192_CFB: return "AES-192-CFB";
        case LEGACY_AES_256_CFB: return "AES-256-CFB";
        case LEGACY_AES_128_OFB: return "AES-128-OFB";
        case LEGACY_AES_192_OFB: return "AES-192-OFB";
        case LEGACY_AES_256_OFB: return "AES-256-OFB";
        case LEGACY_AES_128_ECB: return "AES-128-ECB";
        case LEGACY_AES_192_ECB: return "AES-192-ECB";
        case LEGACY_AES_256_ECB: return "AES-256-ECB";
        case LEGACY_RC2_CBC:     return "RC2-CBC";
        case LEGACY_RC2_ECB:     return "RC2-ECB";
        case LEGACY_DES_CBC:     return "DES-CBC";
        case LEGACY_DES_ECB:     return "DES-ECB";
        case LEGACY_3DES_CBC:    return "3DES-CBC";
        case LEGACY_3DES_ECB:    return "3DES-ECB";
        case LEGACY_RC4:         return "RC4";
        default:                 return "?";
    }
}
// -----------------------------------------------------------------------------

const char* PaddingSchemeName(PaddingScheme scheme)
{
    switch (scheme)
    {
        case PADDING_PKCS7:     return "PKCS7";
        case PADDING_PKCS5:     return "PKCS5";
        case PADDING_ANSI_X923: return "AnsiX923";
        case PADDING_ISO_10126: return "Iso10126";
        case PADDING_ISO_97971: return "Iso97971";
        case PADDING_ZERO:      return "ZeroPadding";
        case PADDING_NONE:      return "NoPadding";
        default:                return "?";
    }
}
// -----------------------------------------------------------------------------

const char* AsymmetricAlgorithmName(AsymmetricAlgorithm algorithm)
{
    switch (algorithm)
    {
        case ASYMMETRIC_RSA_1024: return "RSA-1024";
        case ASYMMETRIC_RSA_2048: return "RSA-2048";
        case ASYMMETRIC_RSA_3072: return "RSA-3072";
        case ASYMMETRIC_RSA_4096: return "RSA-4096";
        default:                  return "?";
    }
}
// -----------------------------------------------------------------------------

const char* HashAlgorithmName(HashAlgorithm algorithm)
{
    switch (algorithm)
    {
        case HASH_MD5:        return "MD5";
        case HASH_SHA1:       return "SHA1";
        case HASH_SHA224:     return "SHA224";
        case HASH_SHA256:     return "SHA256";
        case HASH_SHA384:     return "SHA384";
        case HASH_SHA512:     return "SHA512";
        case HASH_SHA512_256: return "SHA512_256";
        case HASH_SHA3_224:   return "SHA3_224";
        case HASH_SHA3_256:   return "SHA3_256";
        case HASH_SHA3_384:   return "SHA3_384";
        case HASH_SHA3_512:   return "SHA3_512";
        case HASH_BLAKE2B:    return "BLAKE2B";
        case HASH_BLAKE2S:    return "BLAKE2S";
        case HASH_RIPEMD160:  return "RIPEMD160";
        default:              return "?";
    }
}
// -----------------------------------------------------------------------------

int RunProviderFactoryInMemoryRoundTrip(const char* testName, const unsigned char* inputData, std::size_t inputSize)
{
    struct ProviderCase
    {
        ProviderKind kind;
        const char* name;
    };

    const ProviderCase providerCases[] =
    {
        { PROVIDER_MICROSOFT, "Microsoft" },
        { PROVIDER_CRYPTOPP,  "CryptoPP" },
        { PROVIDER_BOTAN,     "Botan" },
        { PROVIDER_OPENSSL,   "OpenSSL" }
    };

    int failures = 0;

    for (std::size_t caseIndex = 0; caseIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++caseIndex)
    {
        const ProviderKind kind = providerCases[caseIndex].kind;
        const char* name = providerCases[caseIndex].name;

        std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
        std::unique_ptr<IAeadCipher> cipher = factory ? factory->CreateAeadCipher(AEAD_AES_256_GCM) : nullptr;
        std::unique_ptr<IRandomSource> randomSource = factory ? factory->CreateRandomSource() : nullptr;
        if (!cipher || !randomSource)
        {
            std::cout << testName << ": FAILED [" << name << "] CreateProviderFactory/CreateAeadCipher/CreateRandomSource" << std::endl;
            ++failures;
            continue;
        }

        const unsigned int keySize = cipher->GetKeySize();
        const unsigned int chunkSize = 512u * 1024u; // smaller than inputSize so progress fires more than once

        std::vector<unsigned char> key(keySize);
        for (unsigned int index = 0; index < keySize; ++index) key[index] = static_cast<unsigned char>(index * 13 + 7);

        if (!cipher->SetKey(key.data(), keySize))
        {
            std::cout << testName << ": FAILED [" << name << "] SetKey" << std::endl;
            ++failures;
            continue;
        }

        unsigned int requiredCiphertextSize = 0;
        cipher->EncryptChunked(*randomSource, inputData, static_cast<unsigned int>(inputSize), chunkSize,
                               nullptr, 0, &requiredCiphertextSize, nullptr, nullptr);

        std::vector<unsigned char> ciphertext(requiredCiphertextSize);
        unsigned int ciphertextSize = 0;
        if (!cipher->EncryptChunked(*randomSource, inputData, static_cast<unsigned int>(inputSize), chunkSize,
                                    ciphertext.data(), requiredCiphertextSize, &ciphertextSize,
                                    &PrintFileProgress, nullptr))
        {
            std::cout << testName << ": FAILED [" << name << "] EncryptChunked" << std::endl;
            ++failures;
            continue;
        }

        std::cout << std::endl;

        unsigned int requiredPlaintextSize = 0;
        cipher->DecryptChunked(ciphertext.data(), ciphertextSize, nullptr, 0, &requiredPlaintextSize, nullptr, nullptr);

        std::vector<unsigned char> decrypted(requiredPlaintextSize);
        unsigned int decryptedSize = 0;
        if (!cipher->DecryptChunked(ciphertext.data(), ciphertextSize, decrypted.data(), requiredPlaintextSize, &decryptedSize,
                                    &PrintFileProgress, nullptr))
        {
            std::cout << testName << ": FAILED [" << name << "] DecryptChunked" << std::endl;
            ++failures;
            continue;
        }

        std::cout << std::endl;

        if (decryptedSize != inputSize || std::memcmp(inputData, decrypted.data(), inputSize) != 0)
        {
            std::cout << testName << ": FAILED [" << name << "] round-trip mismatch" << std::endl;
            ++failures;
            continue;
        }

        std::cout << testName << ": PASSED [" << name << "/AES-256-GCM] (" << inputSize << " bytes)" << std::endl;
    }

    if (failures != 0)
    {
        std::cout << testName << ": " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }

    std::cout << testName << ": PASSED (Microsoft, CryptoPP, Botan, OpenSSL)" << std::endl;
    return NO_ERROR;
}
// -----------------------------------------------------------------------------

int HashViaFactoryInMemory(const char* testName, const unsigned char* inputData, std::size_t inputSize)
{
    struct ProviderCase
    {
        ProviderKind kind;
        const char* name;
    };

    const ProviderCase providerCases[] =
    {
        { PROVIDER_MICROSOFT, "Microsoft" },
        { PROVIDER_CRYPTOPP,  "CryptoPP" },
        { PROVIDER_BOTAN,     "Botan" },
        { PROVIDER_OPENSSL,   "OpenSSL" }
    };

    int failures = 0;

    for (std::size_t caseIndex = 0; caseIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++caseIndex)
    {
        const ProviderKind kind = providerCases[caseIndex].kind;
        const char* name = providerCases[caseIndex].name;

        std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
        std::unique_ptr<IHashService> hashService = factory ? factory->CreateHashService(HASH_SHA256) : nullptr;
        if (!hashService)
        {
            std::cout << testName << ": FAILED [" << name << "] CreateProviderFactory/CreateHashService" << std::endl;
            ++failures;
            continue;
        }

        const unsigned int hashSize = hashService->GetHashSize();
        std::vector<unsigned char> factoryDigest(hashSize);
        if (!hashService->ComputeHash(inputData, static_cast<unsigned int>(inputSize), factoryDigest.data(), hashSize))
        {
            std::cout << testName << ": FAILED [" << name << "] ComputeHash via factory" << std::endl;
            ++failures;
            continue;
        }

        // Cross-check against the CCryptoApi facade (Hash-only 2-argument constructor) -- proves
        // the two layers agree, not just that the Factory layer is internally consistent.
        CCryptoApi cryptoApi(kind, HASH_SHA256);
        std::vector<unsigned char> apiDigest(hashSize);
        int apiDigestSize = 0;
        const int status = cryptoApi.ComputeHashBuffer(inputData, static_cast<int>(inputSize),
                                                        static_cast<int>(hashSize), apiDigest.data(), &apiDigestSize,
                                                        nullptr, nullptr);
        if (status != NO_ERROR || apiDigestSize != static_cast<int>(hashSize) ||
            std::memcmp(apiDigest.data(), factoryDigest.data(), hashSize) != 0)
        {
            std::cout << testName << ": FAILED [" << name << "] CCryptoApi digest mismatch status=" << status << std::endl;
            ++failures;
            continue;
        }

        std::cout << testName << ": PASSED [" << name << "/SHA256] (" << inputSize << " bytes)" << std::endl;
    }

    if (failures != 0)
    {
        std::cout << testName << ": " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }

    std::cout << testName << ": PASSED (Microsoft, CryptoPP, Botan, OpenSSL)" << std::endl;
    return NO_ERROR;
}
// -----------------------------------------------------------------------------

} // namespace

CCryptoApiTester::~CCryptoApiTester()
{
}
// -----------------------------------------------------------------------------

CCryptoApiTester::CCryptoApiTester()
{
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::Run(void)
{
    try
    {
        CCryptoApi cryptoApi;

    #if defined(APP_BUILDER)
        std::cout << "Project define: APP_BUILDER" << std::endl;
    #endif
    #if defined(APP_RUNNER)
        std::cout << "Project define: APP_RUNNER" << std::endl;
    #endif
    #if defined(DLL_BUILDER)
        std::cout << "Project define: DLL_BUILDER" << std::endl;
    #endif
    #if defined(DLL_RUNNER)
        std::cout << "Project define: DLL_RUNNER" << std::endl;
    #endif
    #if defined(LIB_BUILDER)
        std::cout << "Project define: LIB_BUILDER" << std::endl;
    #endif
    #if defined(LIB_RUNNER)
        std::cout << "Project define: LIB_RUNNER" << std::endl;
    #endif

    #if defined(ARCH_X86)
        std::cout << "Architecture define: ARCH_X86" << std::endl;
    #endif
    #if defined(ARCH_X64)
        std::cout << "Architecture define: ARCH_X64" << std::endl;
    #endif
    #if defined(ARCH_WIN32)
        std::cout << "Windows architecture define: ARCH_WIN32" << std::endl;
    #endif
    #if defined(ARCH_WIN64)
        std::cout << "Windows architecture define: ARCH_WIN64" << std::endl;
    #endif

    #if defined(BUILD_DEBUG)
        std::cout << "Build define: BUILD_DEBUG" << std::endl;
    #endif
    #if defined(BUILD_RELEASE)
        std::cout << "Build define: BUILD_RELEASE" << std::endl;
    #endif

        std::cout << "CryptoAPI version: " << cryptoApi.GetVersion() << std::endl;

        std::cout << std::endl;

        return 0;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptDecryptFileTest(void)
{
    try
    {
        std::cout << std::endl;

        const char* password = "T\xC3\xBCst P\xC3\xA4ssw0rd!";
        const char* inputFilePath = "cryptoapi_encfile_test_in.bin";
        const char* encryptedFilePath = "cryptoapi_encfile_test_enc.bin";
        const char* decryptedFilePath = "cryptoapi_encfile_test_out.bin";

        std::vector<unsigned char> inputData(20 * 1048576 + 12345);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunEncryptFileDecryptFileTest: FAILED to write input file" << std::endl;
            return FILE_IO_ERROR;
        }

        CCryptoApi cryptoApi;
        const int encryptStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                        &PrintFileProgress, nullptr);
        if (encryptStatus != NO_ERROR)
        {
            std::cout << "RunEncryptFileDecryptFileTest: FAILED EncryptFile status=" << encryptStatus << std::endl;
            std::remove(inputFilePath);
            return encryptStatus;
        }

        std::cout << std::endl;

        const int decryptStatus = cryptoApi.DecryptFile(password, encryptedFilePath, decryptedFilePath,
                                                        &PrintFileProgress, nullptr);
        if (decryptStatus != NO_ERROR)
        {
            std::cout << "RunEncryptFileDecryptFileTest: FAILED DecryptFile status=" << decryptStatus << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            return decryptStatus;
        }

        std::cout << std::endl;

        std::vector<unsigned char> outputData;
        if (!ReadTesterFile(decryptedFilePath, outputData))
        {
            std::cout << "RunEncryptFileDecryptFileTest: FAILED to read output file" << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            std::remove(decryptedFilePath);
            return FILE_IO_ERROR;
        }

        std::remove(inputFilePath);
        std::remove(encryptedFilePath);
        std::remove(decryptedFilePath);

        if (outputData.size() != inputData.size() ||
            (!inputData.empty() && std::memcmp(&outputData[0], &inputData[0], inputData.size()) != 0))
        {
            std::cout << "RunEncryptFileDecryptFileTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunEncryptFileDecryptFileTest: PASSED (" << inputData.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptFile must
        // stop at the next chunk boundary with OPERATION_CANCELLED and remove the partial output.
        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunEncryptFileDecryptFileTest: FAILED to write cancel-test input file" << std::endl;
            return FILE_IO_ERROR;
        }

        int callCount = 0;
        const int cancelStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                       &CancelAfterThirdChunk, &callCount);
        std::remove(inputFilePath);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunEncryptFileDecryptFileTest: FAILED cancel status=" << cancelStatus << std::endl;
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::ifstream leftoverCheck(encryptedFilePath, std::ios::binary);
        if (leftoverCheck.good())
        {
            std::cout << "RunEncryptFileDecryptFileTest: FAILED cancelled output file was not removed" << std::endl;
            leftoverCheck.close();
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunEncryptFileDecryptFileTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptDecryptStringTest(void)
{
    try
    {
        std::cout << std::endl;

        const char* password = "Str\xC3\xADng T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<char> inputText(2 * 1048576 + 321);
        for (std::size_t index = 0; index < inputText.size(); ++index)
        {
            inputText[index] = static_cast<char>('A' + (index % 26));
        }

        CCryptoApi cryptoApi;

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptString(password, passwordSize,
                                             &inputText[0], static_cast<int>(inputText.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunEncryptStringDecryptStringTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedData(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptString(password, passwordSize,
                                         &inputText[0], static_cast<int>(inputText.size()),
                                         requiredEncryptSize, &encryptedData[0], &encryptedSize,
                                         &PrintFileProgress, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunEncryptStringDecryptStringTest: FAILED EncryptString status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunEncryptStringDecryptStringTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<char> outputText(requiredDecryptSize);
        int outputTextSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         requiredDecryptSize, outputText.empty() ? nullptr : &outputText[0], &outputTextSize,
                                         &PrintFileProgress, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunEncryptStringDecryptStringTest: FAILED DecryptString status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        if (outputTextSize != static_cast<int>(inputText.size()) ||
            std::memcmp(&outputText[0], &inputText[0], inputText.size()) != 0)
        {
            std::cout << "RunEncryptStringDecryptStringTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunEncryptStringDecryptStringTest: PASSED (" << inputText.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptString must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptString(password, passwordSize,
                                                         &inputText[0], static_cast<int>(inputText.size()),
                                                         requiredEncryptSize, &encryptedData[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunEncryptStringDecryptStringTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunEncryptStringDecryptStringTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptDecryptBufferTest(void)
{
    try
    {
        const char* password = "B\xC3\xBC" "ffer T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(2 * 1048576 + 555);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi;

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBuffer(password, passwordSize,
                                             &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunEncryptDecryptBufferTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBuffer(password, passwordSize,
                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                         requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                         &PrintFileProgress, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunEncryptDecryptBufferTest: FAILED EncryptBuffer status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunEncryptDecryptBufferTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                         &PrintFileProgress, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunEncryptDecryptBufferTest: FAILED DecryptBuffer status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunEncryptDecryptBufferTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunEncryptDecryptBufferTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail authentication, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptBuffer("WrongPassword!", 14,
                                         &encryptedBuffer[0], encryptedSize,
                                         static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize,
                                         nullptr, nullptr);
        if (status == NO_ERROR)
        {
            std::cout << "RunEncryptDecryptBufferTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBuffer must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBuffer(password, passwordSize,
                                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                         requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunEncryptDecryptBufferTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunEncryptDecryptBufferTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptDecryptBytesTest(void)
{
    try
    {
        const char* password = "Byt\xC3\xA9s T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(2 * 1048576 + 999);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi;

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBytes(password, passwordSize,
                                            &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                            0, nullptr, &requiredEncryptSize,
                                            nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunEncryptDecryptBytesTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBytes(password, passwordSize,
                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                        requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                        &PrintFileProgress, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunEncryptDecryptBytesTest: FAILED EncryptBytes status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        0, nullptr, &requiredDecryptSize,
                                        nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunEncryptDecryptBytesTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                        &PrintFileProgress, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunEncryptDecryptBytesTest: FAILED DecryptBytes status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunEncryptDecryptBytesTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunEncryptDecryptBytesTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBytes must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBytes(password, passwordSize,
                                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                        requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                        &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunEncryptDecryptBytesTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunEncryptDecryptBytesTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashFileTest(void)
{
    try
    {
        const char* inputFilePath = "cryptoapi_hashfile_test_in.bin";
        const char* knownVectorText = "abc";
        const char* knownVectorHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        std::vector<unsigned char> knownVectorData(knownVectorText, knownVectorText + std::strlen(knownVectorText));
        if (!WriteTesterFile(inputFilePath, knownVectorData))
        {
            std::cout << "RunHashFileTest: FAILED to write known-vector input file" << std::endl;
            return FILE_IO_ERROR;
        }

        CCryptoApi cryptoApi;

        int requiredSize = 0;
        int status = cryptoApi.ComputeHashFile(inputFilePath, 0, nullptr, &requiredSize, nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL || requiredSize != 32)
        {
            std::cout << "RunHashFileTest: FAILED size query status=" << status << std::endl;
            std::remove(inputFilePath);
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> digest(requiredSize);
        int digestSize = 0;
        status = cryptoApi.ComputeHashFile(inputFilePath, requiredSize, &digest[0], &digestSize, &PrintFileProgress, nullptr);
        std::remove(inputFilePath);
        if (status != NO_ERROR)
        {
            std::cout << "RunHashFileTest: FAILED ComputeHashFile status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        int requiredHexSize = 0;
        CUtils::HexEncode(&digest[0], digestSize, false, 0, nullptr, &requiredHexSize);
        std::vector<char> hexText(requiredHexSize);
        int hexSize = 0;
        CUtils::HexEncode(&digest[0], digestSize, false, requiredHexSize, &hexText[0], &hexSize);
        const std::string hexString(hexText.begin(), hexText.end());

        if (hexString != knownVectorHex)
        {
            std::cout << "RunHashFileTest: FAILED SHA-256(\"abc\") via file = " << hexString
                      << " expected " << knownVectorHex << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunHashFileTest: PASSED SHA-256(\"abc\") via file = " << hexString << std::endl;

        // Cancellation: a larger file so the callback fires more than twice, aborting at the 3rd
        // chunk boundary with OPERATION_CANCELLED.
        std::vector<unsigned char> largeData(2 * 1048576 + 999);
        for (std::size_t index = 0; index < largeData.size(); ++index)
        {
            largeData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        if (!WriteTesterFile(inputFilePath, largeData))
        {
            std::cout << "RunHashFileTest: FAILED to write cancel-test input file" << std::endl;
            return FILE_IO_ERROR;
        }

        int callCount = 0;
        int cancelledSize = 0;
        std::vector<unsigned char> cancelDigest(32);
        const int cancelStatus = cryptoApi.ComputeHashFile(inputFilePath, 32, &cancelDigest[0], &cancelledSize,
                                                            &CancelAfterThirdChunk, &callCount);
        std::remove(inputFilePath);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunHashFileTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunHashFileTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashStringTest(void)
{
    try
    {
        const char* knownVectorText = "abc";
        const char* knownVectorHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        const int textSize = static_cast<int>(std::strlen(knownVectorText));

        CCryptoApi cryptoApi;

        int requiredSize = 0;
        int status = cryptoApi.ComputeHashString(knownVectorText, textSize, 0, nullptr, &requiredSize, nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL || requiredSize != 32)
        {
            std::cout << "RunHashStringTest: FAILED size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> digest(requiredSize);
        int digestSize = 0;
        status = cryptoApi.ComputeHashString(knownVectorText, textSize, requiredSize, &digest[0], &digestSize, nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunHashStringTest: FAILED ComputeHashString status=" << status << std::endl;
            return status;
        }

        int requiredHexSize = 0;
        CUtils::HexEncode(&digest[0], digestSize, false, 0, nullptr, &requiredHexSize);
        std::vector<char> hexText(requiredHexSize);
        int hexSize = 0;
        CUtils::HexEncode(&digest[0], digestSize, false, requiredHexSize, &hexText[0], &hexSize);
        const std::string hexString(hexText.begin(), hexText.end());

        if (hexString != knownVectorHex)
        {
            std::cout << "RunHashStringTest: FAILED SHA-256(\"abc\") = " << hexString
                      << " expected " << knownVectorHex << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunHashStringTest: PASSED SHA-256(\"abc\") = " << hexString << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashBufferTest(void)
{
    try
    {
        std::vector<unsigned char> inputBuffer(2 * 1048576 + 555);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi;

        int requiredSize = 0;
        int status = cryptoApi.ComputeHashBuffer(&inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                  0, nullptr, &requiredSize, nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL || requiredSize != 32)
        {
            std::cout << "RunHashBufferTest: FAILED size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> digestA(requiredSize);
        int digestASize = 0;
        status = cryptoApi.ComputeHashBuffer(&inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                             requiredSize, &digestA[0], &digestASize, &PrintFileProgress, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunHashBufferTest: FAILED ComputeHashBuffer status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        // Determinism: hashing the same content again must produce the identical digest.
        std::vector<unsigned char> digestB(requiredSize);
        int digestBSize = 0;
        status = cryptoApi.ComputeHashBuffer(&inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                             requiredSize, &digestB[0], &digestBSize, nullptr, nullptr);
        if (status != NO_ERROR || digestBSize != digestASize || std::memcmp(&digestA[0], &digestB[0], digestASize) != 0)
        {
            std::cout << "RunHashBufferTest: FAILED determinism mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunHashBufferTest: PASSED (" << inputBuffer.size() << " bytes, deterministic)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, ComputeHashBuffer
        // must stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.ComputeHashBuffer(&inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                              requiredSize, &digestA[0], &cancelledSize,
                                                              &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunHashBufferTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunHashBufferTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashBytesTest(void)
{
    try
    {
        std::vector<unsigned char> inputBuffer(2 * 1048576 + 999);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi;

        int requiredSize = 0;
        int status = cryptoApi.ComputeHashBytes(&inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                0, nullptr, &requiredSize, nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL || requiredSize != 32)
        {
            std::cout << "RunHashBytesTest: FAILED size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bytesDigest(requiredSize);
        int bytesDigestSize = 0;
        status = cryptoApi.ComputeHashBytes(&inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                            requiredSize, &bytesDigest[0], &bytesDigestSize, &PrintFileProgress, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunHashBytesTest: FAILED ComputeHashBytes status=" << status << std::endl;
            return status;
        }

        std::cout << std::endl;

        // ComputeHashBytes is an alias of ComputeHashBuffer -- same content must produce the
        // identical digest through either entry point.
        std::vector<unsigned char> bufferDigest(requiredSize);
        int bufferDigestSize = 0;
        status = cryptoApi.ComputeHashBuffer(&inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                             requiredSize, &bufferDigest[0], &bufferDigestSize, nullptr, nullptr);
        if (status != NO_ERROR || bufferDigestSize != bytesDigestSize ||
            std::memcmp(&bufferDigest[0], &bytesDigest[0], bytesDigestSize) != 0)
        {
            std::cout << "RunHashBytesTest: FAILED ComputeHashBuffer/Bytes mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunHashBytesTest: PASSED (" << inputBuffer.size() << " bytes, matches ComputeHashBuffer)" << std::endl;

        // Cancellation, same as RunHashBufferTest.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.ComputeHashBytes(&inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                             requiredSize, &bytesDigest[0], &cancelledSize,
                                                             &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunHashBytesTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunHashBytesTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderEncryptDecryptFileTest(void)
{
    try
    {
        const char* password = "T\xC3\xBCst P\xC3\xA4ssw0rd!";
        const char* inputFilePath = "cryptoapi_encfile_test_in_microsoft.bin";
        const char* encryptedFilePath = "cryptoapi_encfile_test_enc_microsoft.bin";
        const char* decryptedFilePath = "cryptoapi_encfile_test_out_microsoft.bin";

        std::vector<unsigned char> inputData(64 * 1024 + 777);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: FAILED to write input file" << std::endl;
            return FILE_IO_ERROR;
        }

        CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM);
        const int encryptStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                        nullptr, nullptr);
        if (encryptStatus != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: FAILED EncryptFile status=" << encryptStatus << std::endl;
            std::remove(inputFilePath);
            return encryptStatus;
        }

        const int decryptStatus = cryptoApi.DecryptFile(password, encryptedFilePath, decryptedFilePath,
                                                        nullptr, nullptr);
        if (decryptStatus != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: FAILED DecryptFile status=" << decryptStatus << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            return decryptStatus;
        }

        std::vector<unsigned char> outputData;
        if (!ReadTesterFile(decryptedFilePath, outputData))
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: FAILED to read output file" << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            std::remove(decryptedFilePath);
            return FILE_IO_ERROR;
        }

        std::remove(inputFilePath);
        std::remove(encryptedFilePath);
        std::remove(decryptedFilePath);

        if (outputData.size() != inputData.size() ||
            (!inputData.empty() && std::memcmp(&outputData[0], &inputData[0], inputData.size()) != 0))
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: PASSED (" << inputData.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptFile must
        // stop at the next chunk boundary with OPERATION_CANCELLED and remove the partial output.
        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: FAILED to write cancel-test input file" << std::endl;
            return FILE_IO_ERROR;
        }

        int callCount = 0;
        const int cancelStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                       &CancelAfterThirdChunk, &callCount);
        std::remove(inputFilePath);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: FAILED cancel status=" << cancelStatus << std::endl;
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::ifstream leftoverCheck(encryptedFilePath, std::ios::binary);
        if (leftoverCheck.good())
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: FAILED cancelled output file was not removed" << std::endl;
            leftoverCheck.close();
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderEncryptDecryptFileTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderEncryptDecryptStringTest(void)
{
    try
    {
        const char* password = "Str\xC3\xADng T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<char> inputText(8 * 1024 + 321);
        for (std::size_t index = 0; index < inputText.size(); ++index)
        {
            inputText[index] = static_cast<char>('A' + (index % 26));
        }

        CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptString(password, passwordSize,
                                             &inputText[0], static_cast<int>(inputText.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptStringTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedData(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptString(password, passwordSize,
                                         &inputText[0], static_cast<int>(inputText.size()),
                                         requiredEncryptSize, &encryptedData[0], &encryptedSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptStringTest: FAILED EncryptString status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptStringTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<char> outputText(requiredDecryptSize);
        int outputTextSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         requiredDecryptSize, outputText.empty() ? nullptr : &outputText[0], &outputTextSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptStringTest: FAILED DecryptString status=" << status << std::endl;
            return status;
        }

        if (outputTextSize != static_cast<int>(inputText.size()) ||
            std::memcmp(&outputText[0], &inputText[0], inputText.size()) != 0)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptStringTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderEncryptDecryptStringTest: PASSED (" << inputText.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptString must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptString(password, passwordSize,
                                                         &inputText[0], static_cast<int>(inputText.size()),
                                                         requiredEncryptSize, &encryptedData[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptStringTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderEncryptDecryptStringTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderEncryptDecryptBufferTest(void)
{
    try
    {
        const char* password = "B\xC3\xBC" "ffer T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(8 * 1024 + 555);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBuffer(password, passwordSize,
                                             &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBuffer(password, passwordSize,
                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                         requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: FAILED EncryptBuffer status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: FAILED DecryptBuffer status=" << status << std::endl;
            return status;
        }

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail authentication, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptBuffer("WrongPassword!", 14,
                                         &encryptedBuffer[0], encryptedSize,
                                         static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize,
                                         nullptr, nullptr);
        if (status == NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBuffer must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBuffer(password, passwordSize,
                                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                         requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderEncryptDecryptBufferTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderEncryptDecryptBytesTest(void)
{
    try
    {
        const char* password = "Byt\xC3\xA9s T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(8 * 1024 + 999);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBytes(password, passwordSize,
                                            &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                            0, nullptr, &requiredEncryptSize,
                                            nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBytesTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBytes(password, passwordSize,
                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                        requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                        nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBytesTest: FAILED EncryptBytes status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        0, nullptr, &requiredDecryptSize,
                                        nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBytesTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                        nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBytesTest: FAILED DecryptBytes status=" << status << std::endl;
            return status;
        }

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBytesTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderEncryptDecryptBytesTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBytes must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBytes(password, passwordSize,
                                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                        requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                        &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunMicrosoftProviderEncryptDecryptBytesTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderEncryptDecryptBytesTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderEncryptDecryptFileTest(void)
{
    try
    {
        const char* password = "T\xC3\xBCst P\xC3\xA4ssw0rd!";
        const char* inputFilePath = "cryptoapi_encfile_test_in_cryptopp.bin";
        const char* encryptedFilePath = "cryptoapi_encfile_test_enc_cryptopp.bin";
        const char* decryptedFilePath = "cryptoapi_encfile_test_out_cryptopp.bin";

        std::vector<unsigned char> inputData(64 * 1024 + 777);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: FAILED to write input file" << std::endl;
            return FILE_IO_ERROR;
        }

        CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM);
        const int encryptStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                        nullptr, nullptr);
        if (encryptStatus != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: FAILED EncryptFile status=" << encryptStatus << std::endl;
            std::remove(inputFilePath);
            return encryptStatus;
        }

        const int decryptStatus = cryptoApi.DecryptFile(password, encryptedFilePath, decryptedFilePath,
                                                        nullptr, nullptr);
        if (decryptStatus != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: FAILED DecryptFile status=" << decryptStatus << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            return decryptStatus;
        }

        std::vector<unsigned char> outputData;
        if (!ReadTesterFile(decryptedFilePath, outputData))
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: FAILED to read output file" << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            std::remove(decryptedFilePath);
            return FILE_IO_ERROR;
        }

        std::remove(inputFilePath);
        std::remove(encryptedFilePath);
        std::remove(decryptedFilePath);

        if (outputData.size() != inputData.size() ||
            (!inputData.empty() && std::memcmp(&outputData[0], &inputData[0], inputData.size()) != 0))
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: PASSED (" << inputData.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptFile must
        // stop at the next chunk boundary with OPERATION_CANCELLED and remove the partial output.
        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: FAILED to write cancel-test input file" << std::endl;
            return FILE_IO_ERROR;
        }

        int callCount = 0;
        const int cancelStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                       &CancelAfterThirdChunk, &callCount);
        std::remove(inputFilePath);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: FAILED cancel status=" << cancelStatus << std::endl;
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::ifstream leftoverCheck(encryptedFilePath, std::ios::binary);
        if (leftoverCheck.good())
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: FAILED cancelled output file was not removed" << std::endl;
            leftoverCheck.close();
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderEncryptDecryptFileTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderEncryptDecryptStringTest(void)
{
    try
    {
        const char* password = "Str\xC3\xADng T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<char> inputText(8 * 1024 + 321);
        for (std::size_t index = 0; index < inputText.size(); ++index)
        {
            inputText[index] = static_cast<char>('A' + (index % 26));
        }

        CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptString(password, passwordSize,
                                             &inputText[0], static_cast<int>(inputText.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptStringTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedData(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptString(password, passwordSize,
                                         &inputText[0], static_cast<int>(inputText.size()),
                                         requiredEncryptSize, &encryptedData[0], &encryptedSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptStringTest: FAILED EncryptString status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptStringTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<char> outputText(requiredDecryptSize);
        int outputTextSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         requiredDecryptSize, outputText.empty() ? nullptr : &outputText[0], &outputTextSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptStringTest: FAILED DecryptString status=" << status << std::endl;
            return status;
        }

        if (outputTextSize != static_cast<int>(inputText.size()) ||
            std::memcmp(&outputText[0], &inputText[0], inputText.size()) != 0)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptStringTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderEncryptDecryptStringTest: PASSED (" << inputText.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptString must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptString(password, passwordSize,
                                                         &inputText[0], static_cast<int>(inputText.size()),
                                                         requiredEncryptSize, &encryptedData[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptStringTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderEncryptDecryptStringTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderEncryptDecryptBufferTest(void)
{
    try
    {
        const char* password = "B\xC3\xBC" "ffer T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(8 * 1024 + 555);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBuffer(password, passwordSize,
                                             &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBuffer(password, passwordSize,
                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                         requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: FAILED EncryptBuffer status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: FAILED DecryptBuffer status=" << status << std::endl;
            return status;
        }

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail authentication, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptBuffer("WrongPassword!", 14,
                                         &encryptedBuffer[0], encryptedSize,
                                         static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize,
                                         nullptr, nullptr);
        if (status == NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBuffer must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBuffer(password, passwordSize,
                                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                         requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderEncryptDecryptBufferTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderEncryptDecryptBytesTest(void)
{
    try
    {
        const char* password = "Byt\xC3\xA9s T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(8 * 1024 + 999);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBytes(password, passwordSize,
                                            &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                            0, nullptr, &requiredEncryptSize,
                                            nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBytesTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBytes(password, passwordSize,
                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                        requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                        nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBytesTest: FAILED EncryptBytes status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        0, nullptr, &requiredDecryptSize,
                                        nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBytesTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                        nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBytesTest: FAILED DecryptBytes status=" << status << std::endl;
            return status;
        }

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBytesTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderEncryptDecryptBytesTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBytes must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBytes(password, passwordSize,
                                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                        requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                        &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunCryptoPPProviderEncryptDecryptBytesTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderEncryptDecryptBytesTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderEncryptDecryptFileTest(void)
{
    try
    {
        const char* password = "T\xC3\xBCst P\xC3\xA4ssw0rd!";
        const char* inputFilePath = "cryptoapi_encfile_test_in_botan.bin";
        const char* encryptedFilePath = "cryptoapi_encfile_test_enc_botan.bin";
        const char* decryptedFilePath = "cryptoapi_encfile_test_out_botan.bin";

        std::vector<unsigned char> inputData(64 * 1024 + 777);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunBotanProviderEncryptDecryptFileTest: FAILED to write input file" << std::endl;
            return FILE_IO_ERROR;
        }

        CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM);
        const int encryptStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                        nullptr, nullptr);
        if (encryptStatus != NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptFileTest: FAILED EncryptFile status=" << encryptStatus << std::endl;
            std::remove(inputFilePath);
            return encryptStatus;
        }

        const int decryptStatus = cryptoApi.DecryptFile(password, encryptedFilePath, decryptedFilePath,
                                                        nullptr, nullptr);
        if (decryptStatus != NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptFileTest: FAILED DecryptFile status=" << decryptStatus << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            return decryptStatus;
        }

        std::vector<unsigned char> outputData;
        if (!ReadTesterFile(decryptedFilePath, outputData))
        {
            std::cout << "RunBotanProviderEncryptDecryptFileTest: FAILED to read output file" << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            std::remove(decryptedFilePath);
            return FILE_IO_ERROR;
        }

        std::remove(inputFilePath);
        std::remove(encryptedFilePath);
        std::remove(decryptedFilePath);

        if (outputData.size() != inputData.size() ||
            (!inputData.empty() && std::memcmp(&outputData[0], &inputData[0], inputData.size()) != 0))
        {
            std::cout << "RunBotanProviderEncryptDecryptFileTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderEncryptDecryptFileTest: PASSED (" << inputData.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptFile must
        // stop at the next chunk boundary with OPERATION_CANCELLED and remove the partial output.
        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunBotanProviderEncryptDecryptFileTest: FAILED to write cancel-test input file" << std::endl;
            return FILE_IO_ERROR;
        }

        int callCount = 0;
        const int cancelStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                       &CancelAfterThirdChunk, &callCount);
        std::remove(inputFilePath);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunBotanProviderEncryptDecryptFileTest: FAILED cancel status=" << cancelStatus << std::endl;
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::ifstream leftoverCheck(encryptedFilePath, std::ios::binary);
        if (leftoverCheck.good())
        {
            std::cout << "RunBotanProviderEncryptDecryptFileTest: FAILED cancelled output file was not removed" << std::endl;
            leftoverCheck.close();
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderEncryptDecryptFileTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderEncryptDecryptStringTest(void)
{
    try
    {
        const char* password = "Str\xC3\xADng T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<char> inputText(8 * 1024 + 321);
        for (std::size_t index = 0; index < inputText.size(); ++index)
        {
            inputText[index] = static_cast<char>('A' + (index % 26));
        }

        CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptString(password, passwordSize,
                                             &inputText[0], static_cast<int>(inputText.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderEncryptDecryptStringTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedData(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptString(password, passwordSize,
                                         &inputText[0], static_cast<int>(inputText.size()),
                                         requiredEncryptSize, &encryptedData[0], &encryptedSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptStringTest: FAILED EncryptString status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderEncryptDecryptStringTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<char> outputText(requiredDecryptSize);
        int outputTextSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         requiredDecryptSize, outputText.empty() ? nullptr : &outputText[0], &outputTextSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptStringTest: FAILED DecryptString status=" << status << std::endl;
            return status;
        }

        if (outputTextSize != static_cast<int>(inputText.size()) ||
            std::memcmp(&outputText[0], &inputText[0], inputText.size()) != 0)
        {
            std::cout << "RunBotanProviderEncryptDecryptStringTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderEncryptDecryptStringTest: PASSED (" << inputText.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptString must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptString(password, passwordSize,
                                                         &inputText[0], static_cast<int>(inputText.size()),
                                                         requiredEncryptSize, &encryptedData[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunBotanProviderEncryptDecryptStringTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderEncryptDecryptStringTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderEncryptDecryptBufferTest(void)
{
    try
    {
        const char* password = "B\xC3\xBC" "ffer T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(8 * 1024 + 555);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBuffer(password, passwordSize,
                                             &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderEncryptDecryptBufferTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBuffer(password, passwordSize,
                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                         requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptBufferTest: FAILED EncryptBuffer status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderEncryptDecryptBufferTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptBufferTest: FAILED DecryptBuffer status=" << status << std::endl;
            return status;
        }

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunBotanProviderEncryptDecryptBufferTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderEncryptDecryptBufferTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail authentication, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptBuffer("WrongPassword!", 14,
                                         &encryptedBuffer[0], encryptedSize,
                                         static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize,
                                         nullptr, nullptr);
        if (status == NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptBufferTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBuffer must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBuffer(password, passwordSize,
                                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                         requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunBotanProviderEncryptDecryptBufferTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderEncryptDecryptBufferTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderEncryptDecryptBytesTest(void)
{
    try
    {
        const char* password = "Byt\xC3\xA9s T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(8 * 1024 + 999);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBytes(password, passwordSize,
                                            &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                            0, nullptr, &requiredEncryptSize,
                                            nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderEncryptDecryptBytesTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBytes(password, passwordSize,
                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                        requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                        nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptBytesTest: FAILED EncryptBytes status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        0, nullptr, &requiredDecryptSize,
                                        nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderEncryptDecryptBytesTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                        nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderEncryptDecryptBytesTest: FAILED DecryptBytes status=" << status << std::endl;
            return status;
        }

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunBotanProviderEncryptDecryptBytesTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderEncryptDecryptBytesTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBytes must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBytes(password, passwordSize,
                                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                        requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                        &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunBotanProviderEncryptDecryptBytesTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderEncryptDecryptBytesTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderEncryptDecryptFileTest(void)
{
    try
    {
        const char* password = "T\xC3\xBCst P\xC3\xA4ssw0rd!";
        const char* inputFilePath = "cryptoapi_encfile_test_in_openssl.bin";
        const char* encryptedFilePath = "cryptoapi_encfile_test_enc_openssl.bin";
        const char* decryptedFilePath = "cryptoapi_encfile_test_out_openssl.bin";

        std::vector<unsigned char> inputData(64 * 1024 + 777);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunOpenSslProviderEncryptDecryptFileTest: FAILED to write input file" << std::endl;
            return FILE_IO_ERROR;
        }

        CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM);
        const int encryptStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                        nullptr, nullptr);
        if (encryptStatus != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptFileTest: FAILED EncryptFile status=" << encryptStatus << std::endl;
            std::remove(inputFilePath);
            return encryptStatus;
        }

        const int decryptStatus = cryptoApi.DecryptFile(password, encryptedFilePath, decryptedFilePath,
                                                        nullptr, nullptr);
        if (decryptStatus != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptFileTest: FAILED DecryptFile status=" << decryptStatus << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            return decryptStatus;
        }

        std::vector<unsigned char> outputData;
        if (!ReadTesterFile(decryptedFilePath, outputData))
        {
            std::cout << "RunOpenSslProviderEncryptDecryptFileTest: FAILED to read output file" << std::endl;
            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            std::remove(decryptedFilePath);
            return FILE_IO_ERROR;
        }

        std::remove(inputFilePath);
        std::remove(encryptedFilePath);
        std::remove(decryptedFilePath);

        if (outputData.size() != inputData.size() ||
            (!inputData.empty() && std::memcmp(&outputData[0], &inputData[0], inputData.size()) != 0))
        {
            std::cout << "RunOpenSslProviderEncryptDecryptFileTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderEncryptDecryptFileTest: PASSED (" << inputData.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptFile must
        // stop at the next chunk boundary with OPERATION_CANCELLED and remove the partial output.
        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunOpenSslProviderEncryptDecryptFileTest: FAILED to write cancel-test input file" << std::endl;
            return FILE_IO_ERROR;
        }

        int callCount = 0;
        const int cancelStatus = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath,
                                                       &CancelAfterThirdChunk, &callCount);
        std::remove(inputFilePath);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptFileTest: FAILED cancel status=" << cancelStatus << std::endl;
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::ifstream leftoverCheck(encryptedFilePath, std::ios::binary);
        if (leftoverCheck.good())
        {
            std::cout << "RunOpenSslProviderEncryptDecryptFileTest: FAILED cancelled output file was not removed" << std::endl;
            leftoverCheck.close();
            std::remove(encryptedFilePath);
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderEncryptDecryptFileTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderEncryptDecryptStringTest(void)
{
    try
    {
        const char* password = "Str\xC3\xADng T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<char> inputText(8 * 1024 + 321);
        for (std::size_t index = 0; index < inputText.size(); ++index)
        {
            inputText[index] = static_cast<char>('A' + (index % 26));
        }

        CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptString(password, passwordSize,
                                             &inputText[0], static_cast<int>(inputText.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptStringTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedData(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptString(password, passwordSize,
                                         &inputText[0], static_cast<int>(inputText.size()),
                                         requiredEncryptSize, &encryptedData[0], &encryptedSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptStringTest: FAILED EncryptString status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptStringTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<char> outputText(requiredDecryptSize);
        int outputTextSize = 0;
        status = cryptoApi.DecryptString(password, passwordSize,
                                         &encryptedData[0], encryptedSize,
                                         requiredDecryptSize, outputText.empty() ? nullptr : &outputText[0], &outputTextSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptStringTest: FAILED DecryptString status=" << status << std::endl;
            return status;
        }

        if (outputTextSize != static_cast<int>(inputText.size()) ||
            std::memcmp(&outputText[0], &inputText[0], inputText.size()) != 0)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptStringTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderEncryptDecryptStringTest: PASSED (" << inputText.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptString must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptString(password, passwordSize,
                                                         &inputText[0], static_cast<int>(inputText.size()),
                                                         requiredEncryptSize, &encryptedData[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptStringTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderEncryptDecryptStringTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderEncryptDecryptBufferTest(void)
{
    try
    {
        const char* password = "B\xC3\xBC" "ffer T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(8 * 1024 + 555);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBuffer(password, passwordSize,
                                             &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                             0, nullptr, &requiredEncryptSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBuffer(password, passwordSize,
                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                         requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: FAILED EncryptBuffer status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         0, nullptr, &requiredDecryptSize,
                                         nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBuffer(password, passwordSize,
                                         &encryptedBuffer[0], encryptedSize,
                                         requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: FAILED DecryptBuffer status=" << status << std::endl;
            return status;
        }

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail authentication, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptBuffer("WrongPassword!", 14,
                                         &encryptedBuffer[0], encryptedSize,
                                         static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize,
                                         nullptr, nullptr);
        if (status == NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBuffer must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBuffer(password, passwordSize,
                                                         &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                         requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                         &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderEncryptDecryptBufferTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderEncryptDecryptBytesTest(void)
{
    try
    {
        const char* password = "Byt\xC3\xA9s T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(8 * 1024 + 999);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM);

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptBytes(password, passwordSize,
                                            &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                            0, nullptr, &requiredEncryptSize,
                                            nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBytesTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptBytes(password, passwordSize,
                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                        requiredEncryptSize, &encryptedBuffer[0], &encryptedSize,
                                        nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBytesTest: FAILED EncryptBytes status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        0, nullptr, &requiredDecryptSize,
                                        nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBytesTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptBytes(password, passwordSize,
                                        &encryptedBuffer[0], encryptedSize,
                                        requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize,
                                        nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBytesTest: FAILED DecryptBytes status=" << status << std::endl;
            return status;
        }

        if (outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(&outputBuffer[0], &inputBuffer[0], inputBuffer.size()) != 0)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBytesTest: FAILED content mismatch" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderEncryptDecryptBytesTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Cancellation: the callback returns false starting from its 3rd call, EncryptBytes must
        // stop at the next chunk boundary with OPERATION_CANCELLED.
        int callCount = 0;
        int cancelledSize = 0;
        const int cancelStatus = cryptoApi.EncryptBytes(password, passwordSize,
                                                        &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                        requiredEncryptSize, &encryptedBuffer[0], &cancelledSize,
                                                        &CancelAfterThirdChunk, &callCount);
        if (cancelStatus != OPERATION_CANCELLED)
        {
            std::cout << "RunOpenSslProviderEncryptDecryptBytesTest: FAILED cancel status=" << cancelStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderEncryptDecryptBytesTest: PASSED cancellation" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderAsymmetricTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048);

        const int keyPairStatus = cryptoApi.GenerateAsymmetricKeyPair();
        if (keyPairStatus != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderAsymmetricTest: FAILED GenerateAsymmetricKeyPair status=" << keyPairStatus << std::endl;
            return keyPairStatus;
        }

        const int maxPlaintextSize = cryptoApi.GetMaxAsymmetricPlaintextSize();
        const int ciphertextSize = cryptoApi.GetAsymmetricCiphertextSize();
        if (maxPlaintextSize <= 0 || ciphertextSize <= 0)
        {
            std::cout << "RunMicrosoftProviderAsymmetricTest: FAILED sizes maxPlaintext=" << maxPlaintextSize
                      << " ciphertext=" << ciphertextSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const unsigned char plaintext[] = "RSA round trip via CCryptoApi";
        const int plaintextSize = static_cast<int>(sizeof(plaintext) - 1);
        if (plaintextSize > maxPlaintextSize)
        {
            std::cout << "RunMicrosoftProviderAsymmetricTest: FAILED plaintext exceeds max" << std::endl;
            return UNEXPECTED_ERROR;
        }

        int requiredCiphertextSize = 0;
        int status = cryptoApi.EncryptWithPublicKey(plaintext, plaintextSize, 0, nullptr, &requiredCiphertextSize);
        if (status != BUFFER_TOO_SMALL || requiredCiphertextSize != ciphertextSize)
        {
            std::cout << "RunMicrosoftProviderAsymmetricTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> ciphertext(requiredCiphertextSize);
        int actualCiphertextSize = 0;
        status = cryptoApi.EncryptWithPublicKey(plaintext, plaintextSize, requiredCiphertextSize, &ciphertext[0], &actualCiphertextSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderAsymmetricTest: FAILED EncryptWithPublicKey status=" << status << std::endl;
            return status;
        }

        int requiredPlaintextSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&ciphertext[0], actualCiphertextSize, 0, nullptr, &requiredPlaintextSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderAsymmetricTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> decrypted(requiredPlaintextSize);
        int decryptedSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&ciphertext[0], actualCiphertextSize, requiredPlaintextSize, decrypted.empty() ? nullptr : &decrypted[0], &decryptedSize);
        if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(decrypted.data(), plaintext, plaintextSize) != 0)
        {
            std::cout << "RunMicrosoftProviderAsymmetricTest: FAILED Decrypt/mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderAsymmetricTest: PASSED (maxPlaintext=" << maxPlaintextSize
                  << " ciphertext=" << ciphertextSize << ")" << std::endl;

        // Tampered ciphertext must fail OAEP integrity, not silently return garbage.
        std::vector<unsigned char> tampered(ciphertext.begin(), ciphertext.begin() + actualCiphertextSize);
        tampered[0] ^= 0xFF;
        std::vector<unsigned char> tamperedOutput(requiredPlaintextSize);
        int tamperedSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&tampered[0], actualCiphertextSize, requiredPlaintextSize, tamperedOutput.empty() ? nullptr : &tamperedOutput[0], &tamperedSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderAsymmetricTest: FAILED tampered ciphertext accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderAsymmetricTest: PASSED tampered ciphertext rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderAsymmetricTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048);

        const int keyPairStatus = cryptoApi.GenerateAsymmetricKeyPair();
        if (keyPairStatus != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderAsymmetricTest: FAILED GenerateAsymmetricKeyPair status=" << keyPairStatus << std::endl;
            return keyPairStatus;
        }

        const int maxPlaintextSize = cryptoApi.GetMaxAsymmetricPlaintextSize();
        const int ciphertextSize = cryptoApi.GetAsymmetricCiphertextSize();
        if (maxPlaintextSize <= 0 || ciphertextSize <= 0)
        {
            std::cout << "RunCryptoPPProviderAsymmetricTest: FAILED sizes maxPlaintext=" << maxPlaintextSize
                      << " ciphertext=" << ciphertextSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const unsigned char plaintext[] = "RSA round trip via CCryptoApi";
        const int plaintextSize = static_cast<int>(sizeof(plaintext) - 1);
        if (plaintextSize > maxPlaintextSize)
        {
            std::cout << "RunCryptoPPProviderAsymmetricTest: FAILED plaintext exceeds max" << std::endl;
            return UNEXPECTED_ERROR;
        }

        int requiredCiphertextSize = 0;
        int status = cryptoApi.EncryptWithPublicKey(plaintext, plaintextSize, 0, nullptr, &requiredCiphertextSize);
        if (status != BUFFER_TOO_SMALL || requiredCiphertextSize != ciphertextSize)
        {
            std::cout << "RunCryptoPPProviderAsymmetricTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> ciphertext(requiredCiphertextSize);
        int actualCiphertextSize = 0;
        status = cryptoApi.EncryptWithPublicKey(plaintext, plaintextSize, requiredCiphertextSize, &ciphertext[0], &actualCiphertextSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderAsymmetricTest: FAILED EncryptWithPublicKey status=" << status << std::endl;
            return status;
        }

        int requiredPlaintextSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&ciphertext[0], actualCiphertextSize, 0, nullptr, &requiredPlaintextSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderAsymmetricTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> decrypted(requiredPlaintextSize);
        int decryptedSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&ciphertext[0], actualCiphertextSize, requiredPlaintextSize, decrypted.empty() ? nullptr : &decrypted[0], &decryptedSize);
        if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(decrypted.data(), plaintext, plaintextSize) != 0)
        {
            std::cout << "RunCryptoPPProviderAsymmetricTest: FAILED Decrypt/mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderAsymmetricTest: PASSED (maxPlaintext=" << maxPlaintextSize
                  << " ciphertext=" << ciphertextSize << ")" << std::endl;

        // Tampered ciphertext must fail OAEP integrity, not silently return garbage.
        std::vector<unsigned char> tampered(ciphertext.begin(), ciphertext.begin() + actualCiphertextSize);
        tampered[0] ^= 0xFF;
        std::vector<unsigned char> tamperedOutput(requiredPlaintextSize);
        int tamperedSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&tampered[0], actualCiphertextSize, requiredPlaintextSize, tamperedOutput.empty() ? nullptr : &tamperedOutput[0], &tamperedSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderAsymmetricTest: FAILED tampered ciphertext accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderAsymmetricTest: PASSED tampered ciphertext rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderAsymmetricTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048);

        const int keyPairStatus = cryptoApi.GenerateAsymmetricKeyPair();
        if (keyPairStatus != NO_ERROR)
        {
            std::cout << "RunBotanProviderAsymmetricTest: FAILED GenerateAsymmetricKeyPair status=" << keyPairStatus << std::endl;
            return keyPairStatus;
        }

        const int maxPlaintextSize = cryptoApi.GetMaxAsymmetricPlaintextSize();
        const int ciphertextSize = cryptoApi.GetAsymmetricCiphertextSize();
        if (maxPlaintextSize <= 0 || ciphertextSize <= 0)
        {
            std::cout << "RunBotanProviderAsymmetricTest: FAILED sizes maxPlaintext=" << maxPlaintextSize
                      << " ciphertext=" << ciphertextSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const unsigned char plaintext[] = "RSA round trip via CCryptoApi";
        const int plaintextSize = static_cast<int>(sizeof(plaintext) - 1);
        if (plaintextSize > maxPlaintextSize)
        {
            std::cout << "RunBotanProviderAsymmetricTest: FAILED plaintext exceeds max" << std::endl;
            return UNEXPECTED_ERROR;
        }

        int requiredCiphertextSize = 0;
        int status = cryptoApi.EncryptWithPublicKey(plaintext, plaintextSize, 0, nullptr, &requiredCiphertextSize);
        if (status != BUFFER_TOO_SMALL || requiredCiphertextSize != ciphertextSize)
        {
            std::cout << "RunBotanProviderAsymmetricTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> ciphertext(requiredCiphertextSize);
        int actualCiphertextSize = 0;
        status = cryptoApi.EncryptWithPublicKey(plaintext, plaintextSize, requiredCiphertextSize, &ciphertext[0], &actualCiphertextSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderAsymmetricTest: FAILED EncryptWithPublicKey status=" << status << std::endl;
            return status;
        }

        int requiredPlaintextSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&ciphertext[0], actualCiphertextSize, 0, nullptr, &requiredPlaintextSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderAsymmetricTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> decrypted(requiredPlaintextSize);
        int decryptedSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&ciphertext[0], actualCiphertextSize, requiredPlaintextSize, decrypted.empty() ? nullptr : &decrypted[0], &decryptedSize);
        if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(decrypted.data(), plaintext, plaintextSize) != 0)
        {
            std::cout << "RunBotanProviderAsymmetricTest: FAILED Decrypt/mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderAsymmetricTest: PASSED (maxPlaintext=" << maxPlaintextSize
                  << " ciphertext=" << ciphertextSize << ")" << std::endl;

        // Tampered ciphertext must fail OAEP integrity, not silently return garbage.
        std::vector<unsigned char> tampered(ciphertext.begin(), ciphertext.begin() + actualCiphertextSize);
        tampered[0] ^= 0xFF;
        std::vector<unsigned char> tamperedOutput(requiredPlaintextSize);
        int tamperedSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&tampered[0], actualCiphertextSize, requiredPlaintextSize, tamperedOutput.empty() ? nullptr : &tamperedOutput[0], &tamperedSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunBotanProviderAsymmetricTest: FAILED tampered ciphertext accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderAsymmetricTest: PASSED tampered ciphertext rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderAsymmetricTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048);

        const int keyPairStatus = cryptoApi.GenerateAsymmetricKeyPair();
        if (keyPairStatus != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderAsymmetricTest: FAILED GenerateAsymmetricKeyPair status=" << keyPairStatus << std::endl;
            return keyPairStatus;
        }

        const int maxPlaintextSize = cryptoApi.GetMaxAsymmetricPlaintextSize();
        const int ciphertextSize = cryptoApi.GetAsymmetricCiphertextSize();
        if (maxPlaintextSize <= 0 || ciphertextSize <= 0)
        {
            std::cout << "RunOpenSslProviderAsymmetricTest: FAILED sizes maxPlaintext=" << maxPlaintextSize
                      << " ciphertext=" << ciphertextSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const unsigned char plaintext[] = "RSA round trip via CCryptoApi";
        const int plaintextSize = static_cast<int>(sizeof(plaintext) - 1);
        if (plaintextSize > maxPlaintextSize)
        {
            std::cout << "RunOpenSslProviderAsymmetricTest: FAILED plaintext exceeds max" << std::endl;
            return UNEXPECTED_ERROR;
        }

        int requiredCiphertextSize = 0;
        int status = cryptoApi.EncryptWithPublicKey(plaintext, plaintextSize, 0, nullptr, &requiredCiphertextSize);
        if (status != BUFFER_TOO_SMALL || requiredCiphertextSize != ciphertextSize)
        {
            std::cout << "RunOpenSslProviderAsymmetricTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> ciphertext(requiredCiphertextSize);
        int actualCiphertextSize = 0;
        status = cryptoApi.EncryptWithPublicKey(plaintext, plaintextSize, requiredCiphertextSize, &ciphertext[0], &actualCiphertextSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderAsymmetricTest: FAILED EncryptWithPublicKey status=" << status << std::endl;
            return status;
        }

        int requiredPlaintextSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&ciphertext[0], actualCiphertextSize, 0, nullptr, &requiredPlaintextSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderAsymmetricTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> decrypted(requiredPlaintextSize);
        int decryptedSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&ciphertext[0], actualCiphertextSize, requiredPlaintextSize, decrypted.empty() ? nullptr : &decrypted[0], &decryptedSize);
        if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(decrypted.data(), plaintext, plaintextSize) != 0)
        {
            std::cout << "RunOpenSslProviderAsymmetricTest: FAILED Decrypt/mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderAsymmetricTest: PASSED (maxPlaintext=" << maxPlaintextSize
                  << " ciphertext=" << ciphertextSize << ")" << std::endl;

        // Tampered ciphertext must fail OAEP integrity, not silently return garbage.
        std::vector<unsigned char> tampered(ciphertext.begin(), ciphertext.begin() + actualCiphertextSize);
        tampered[0] ^= 0xFF;
        std::vector<unsigned char> tamperedOutput(requiredPlaintextSize);
        int tamperedSize = 0;
        status = cryptoApi.DecryptWithPrivateKey(&tampered[0], actualCiphertextSize, requiredPlaintextSize, tamperedOutput.empty() ? nullptr : &tamperedOutput[0], &tamperedSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunOpenSslProviderAsymmetricTest: FAILED tampered ciphertext accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderAsymmetricTest: PASSED tampered ciphertext rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderLegacyTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC);

        const char* password = "L\xC3\xA9gacy T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(5000 + 777);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                                   &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                   0, nullptr, &requiredEncryptSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderLegacyTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                               &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                               requiredEncryptSize, &encryptedBuffer[0], &encryptedSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderLegacyTest: FAILED EncryptLegacyBuffer status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &encryptedBuffer[0], encryptedSize,
                                               0, nullptr, &requiredDecryptSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunMicrosoftProviderLegacyTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &encryptedBuffer[0], encryptedSize,
                                               requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize);
        if (status != NO_ERROR || outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(outputBuffer.data(), inputBuffer.data(), inputBuffer.size()) != 0)
        {
            std::cout << "RunMicrosoftProviderLegacyTest: FAILED Decrypt/mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderLegacyTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail the MAC check, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer("WrongPassword!", 14,
                                               &encryptedBuffer[0], encryptedSize,
                                               static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderLegacyTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Tampered ciphertext must fail the MAC check (fail-closed: never reaches the cipher).
        std::vector<unsigned char> tamperedCiphertext(encryptedBuffer);
        tamperedCiphertext[tamperedCiphertext.size() / 2] ^= 0xFF;
        std::vector<unsigned char> tamperedOutput(outputBuffer.size());
        int tamperedOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &tamperedCiphertext[0], static_cast<int>(tamperedCiphertext.size()),
                                               static_cast<int>(tamperedOutput.size()), &tamperedOutput[0], &tamperedOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderLegacyTest: FAILED tampered ciphertext accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Tampered MAC tag (last byte) must also fail.
        std::vector<unsigned char> tamperedMac(encryptedBuffer);
        tamperedMac[tamperedMac.size() - 1] ^= 0xFF;
        std::vector<unsigned char> tamperedMacOutput(outputBuffer.size());
        int tamperedMacOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &tamperedMac[0], static_cast<int>(tamperedMac.size()),
                                               static_cast<int>(tamperedMacOutput.size()), &tamperedMacOutput[0], &tamperedMacOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderLegacyTest: FAILED tampered MAC accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderLegacyTest: PASSED wrong password / tampered ciphertext / tampered MAC all rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderLegacyTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC);

        const char* password = "L\xC3\xA9gacy T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(5000 + 777);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                                   &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                   0, nullptr, &requiredEncryptSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderLegacyTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                               &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                               requiredEncryptSize, &encryptedBuffer[0], &encryptedSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderLegacyTest: FAILED EncryptLegacyBuffer status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &encryptedBuffer[0], encryptedSize,
                                               0, nullptr, &requiredDecryptSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunCryptoPPProviderLegacyTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &encryptedBuffer[0], encryptedSize,
                                               requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize);
        if (status != NO_ERROR || outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(outputBuffer.data(), inputBuffer.data(), inputBuffer.size()) != 0)
        {
            std::cout << "RunCryptoPPProviderLegacyTest: FAILED Decrypt/mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderLegacyTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail the MAC check, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer("WrongPassword!", 14,
                                               &encryptedBuffer[0], encryptedSize,
                                               static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderLegacyTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Tampered ciphertext must fail the MAC check (fail-closed: never reaches the cipher).
        std::vector<unsigned char> tamperedCiphertext(encryptedBuffer);
        tamperedCiphertext[tamperedCiphertext.size() / 2] ^= 0xFF;
        std::vector<unsigned char> tamperedOutput(outputBuffer.size());
        int tamperedOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &tamperedCiphertext[0], static_cast<int>(tamperedCiphertext.size()),
                                               static_cast<int>(tamperedOutput.size()), &tamperedOutput[0], &tamperedOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderLegacyTest: FAILED tampered ciphertext accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Tampered MAC tag (last byte) must also fail.
        std::vector<unsigned char> tamperedMac(encryptedBuffer);
        tamperedMac[tamperedMac.size() - 1] ^= 0xFF;
        std::vector<unsigned char> tamperedMacOutput(outputBuffer.size());
        int tamperedMacOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &tamperedMac[0], static_cast<int>(tamperedMac.size()),
                                               static_cast<int>(tamperedMacOutput.size()), &tamperedMacOutput[0], &tamperedMacOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderLegacyTest: FAILED tampered MAC accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderLegacyTest: PASSED wrong password / tampered ciphertext / tampered MAC all rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderLegacyTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC);

        const char* password = "L\xC3\xA9gacy T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(5000 + 777);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                                   &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                   0, nullptr, &requiredEncryptSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderLegacyTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                               &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                               requiredEncryptSize, &encryptedBuffer[0], &encryptedSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderLegacyTest: FAILED EncryptLegacyBuffer status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &encryptedBuffer[0], encryptedSize,
                                               0, nullptr, &requiredDecryptSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunBotanProviderLegacyTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &encryptedBuffer[0], encryptedSize,
                                               requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize);
        if (status != NO_ERROR || outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(outputBuffer.data(), inputBuffer.data(), inputBuffer.size()) != 0)
        {
            std::cout << "RunBotanProviderLegacyTest: FAILED Decrypt/mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderLegacyTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail the MAC check, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer("WrongPassword!", 14,
                                               &encryptedBuffer[0], encryptedSize,
                                               static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunBotanProviderLegacyTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Tampered ciphertext must fail the MAC check (fail-closed: never reaches the cipher).
        std::vector<unsigned char> tamperedCiphertext(encryptedBuffer);
        tamperedCiphertext[tamperedCiphertext.size() / 2] ^= 0xFF;
        std::vector<unsigned char> tamperedOutput(outputBuffer.size());
        int tamperedOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &tamperedCiphertext[0], static_cast<int>(tamperedCiphertext.size()),
                                               static_cast<int>(tamperedOutput.size()), &tamperedOutput[0], &tamperedOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunBotanProviderLegacyTest: FAILED tampered ciphertext accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Tampered MAC tag (last byte) must also fail.
        std::vector<unsigned char> tamperedMac(encryptedBuffer);
        tamperedMac[tamperedMac.size() - 1] ^= 0xFF;
        std::vector<unsigned char> tamperedMacOutput(outputBuffer.size());
        int tamperedMacOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &tamperedMac[0], static_cast<int>(tamperedMac.size()),
                                               static_cast<int>(tamperedMacOutput.size()), &tamperedMacOutput[0], &tamperedMacOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunBotanProviderLegacyTest: FAILED tampered MAC accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderLegacyTest: PASSED wrong password / tampered ciphertext / tampered MAC all rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderLegacyTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC);

        const char* password = "L\xC3\xA9gacy T\xC3\xA9st P\xC3\xA4ss!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        std::vector<unsigned char> inputBuffer(5000 + 777);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        int requiredEncryptSize = 0;
        int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                                   &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                                   0, nullptr, &requiredEncryptSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderLegacyTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
        int encryptedSize = 0;
        status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                               &inputBuffer[0], static_cast<int>(inputBuffer.size()),
                                               requiredEncryptSize, &encryptedBuffer[0], &encryptedSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderLegacyTest: FAILED EncryptLegacyBuffer status=" << status << std::endl;
            return status;
        }

        int requiredDecryptSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &encryptedBuffer[0], encryptedSize,
                                               0, nullptr, &requiredDecryptSize);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunOpenSslProviderLegacyTest: FAILED decrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outputBuffer(requiredDecryptSize);
        int outputBufferSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &encryptedBuffer[0], encryptedSize,
                                               requiredDecryptSize, outputBuffer.empty() ? nullptr : &outputBuffer[0], &outputBufferSize);
        if (status != NO_ERROR || outputBufferSize != static_cast<int>(inputBuffer.size()) ||
            std::memcmp(outputBuffer.data(), inputBuffer.data(), inputBuffer.size()) != 0)
        {
            std::cout << "RunOpenSslProviderLegacyTest: FAILED Decrypt/mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderLegacyTest: PASSED (" << inputBuffer.size() << " bytes)" << std::endl;

        // Wrong password must fail the MAC check, not silently return garbage.
        std::vector<unsigned char> wrongOutput(outputBuffer.size());
        int wrongOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer("WrongPassword!", 14,
                                               &encryptedBuffer[0], encryptedSize,
                                               static_cast<int>(wrongOutput.size()), &wrongOutput[0], &wrongOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunOpenSslProviderLegacyTest: FAILED wrong password accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Tampered ciphertext must fail the MAC check (fail-closed: never reaches the cipher).
        std::vector<unsigned char> tamperedCiphertext(encryptedBuffer);
        tamperedCiphertext[tamperedCiphertext.size() / 2] ^= 0xFF;
        std::vector<unsigned char> tamperedOutput(outputBuffer.size());
        int tamperedOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &tamperedCiphertext[0], static_cast<int>(tamperedCiphertext.size()),
                                               static_cast<int>(tamperedOutput.size()), &tamperedOutput[0], &tamperedOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunOpenSslProviderLegacyTest: FAILED tampered ciphertext accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Tampered MAC tag (last byte) must also fail.
        std::vector<unsigned char> tamperedMac(encryptedBuffer);
        tamperedMac[tamperedMac.size() - 1] ^= 0xFF;
        std::vector<unsigned char> tamperedMacOutput(outputBuffer.size());
        int tamperedMacOutputSize = 0;
        status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                               &tamperedMac[0], static_cast<int>(tamperedMac.size()),
                                               static_cast<int>(tamperedMacOutput.size()), &tamperedMacOutput[0], &tamperedMacOutputSize);
        if (status == NO_ERROR)
        {
            std::cout << "RunOpenSslProviderLegacyTest: FAILED tampered MAC accepted" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderLegacyTest: PASSED wrong password / tampered ciphertext / tampered MAC all rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunLegacyAlgorithmsTest(void)
{
    try
    {
        struct ProviderCase
        {
            ProviderKind kind;
            const char* name;
        };

        const ProviderCase providerCases[] =
        {
            { PROVIDER_MICROSOFT, "Microsoft" },
            { PROVIDER_CRYPTOPP,  "CryptoPP" },
            { PROVIDER_BOTAN,     "Botan" },
            { PROVIDER_OPENSSL,   "OpenSSL" }
        };

        const LegacySymmetricAlgorithm legacyAlgorithms[] =
        {
            LEGACY_AES_128_CBC, LEGACY_AES_192_CBC, LEGACY_AES_256_CBC,
            LEGACY_AES_128_CTR, LEGACY_AES_192_CTR, LEGACY_AES_256_CTR,
            LEGACY_AES_128_CFB, LEGACY_AES_192_CFB, LEGACY_AES_256_CFB,
            LEGACY_AES_128_OFB, LEGACY_AES_192_OFB, LEGACY_AES_256_OFB,
            LEGACY_AES_128_ECB, LEGACY_AES_192_ECB, LEGACY_AES_256_ECB,
            LEGACY_RC2_CBC, LEGACY_RC2_ECB,
            LEGACY_DES_CBC, LEGACY_DES_ECB,
            LEGACY_3DES_CBC, LEGACY_3DES_ECB,
            LEGACY_RC4
        };

        const char* password = "L\xC3\xA9gacyAllAlgos!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        unsigned char plaintext[64];
        for (std::size_t index = 0; index < sizeof(plaintext); ++index)
        {
            plaintext[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t providerIndex = 0; providerIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++providerIndex)
        {
            const ProviderKind kind = providerCases[providerIndex].kind;
            const char* providerName = providerCases[providerIndex].name;

            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
            if (!factory)
            {
                std::cout << "RunLegacyAlgorithmsTest: FAILED [" << providerName << "] CreateProviderFactory" << std::endl;
                ++failures;
                continue;
            }

            for (std::size_t algoIndex = 0; algoIndex < sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]); ++algoIndex)
            {
                const LegacySymmetricAlgorithm algorithm = legacyAlgorithms[algoIndex];
                const char* algorithmName = LegacyAlgorithmName(algorithm);
                const bool supported = factory->SupportsLegacyAlgorithm(algorithm);

                CCryptoApi cryptoApi(kind, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, algorithm);

                int requiredEncryptSize = 0;
                int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                                           plaintext, static_cast<int>(sizeof(plaintext)),
                                                           0, nullptr, &requiredEncryptSize);

                if (!supported)
                {
                    if (status == BUFFER_TOO_SMALL)
                    {
                        std::cout << "RunLegacyAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                                  << "] expected unsupported but got a size" << std::endl;
                        ++failures;
                    }
                    else
                    {
                        std::cout << "RunLegacyAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                                  << "] correctly unsupported" << std::endl;
                    }
                    continue;
                }

                ++supportedCount;

                if (status != BUFFER_TOO_SMALL)
                {
                    std::cout << "RunLegacyAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] encrypt size query status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
                int encryptedSize = 0;
                status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                                       plaintext, static_cast<int>(sizeof(plaintext)),
                                                       requiredEncryptSize, &encryptedBuffer[0], &encryptedSize);
                if (status != NO_ERROR)
                {
                    std::cout << "RunLegacyAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] EncryptLegacyBuffer status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                int requiredDecryptSize = 0;
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                                       &encryptedBuffer[0], encryptedSize,
                                                       0, nullptr, &requiredDecryptSize);
                if (status != BUFFER_TOO_SMALL)
                {
                    std::cout << "RunLegacyAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] decrypt size query status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> decryptedBuffer(requiredDecryptSize);
                int decryptedSize = 0;
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                                       &encryptedBuffer[0], encryptedSize,
                                                       requiredDecryptSize, decryptedBuffer.empty() ? nullptr : &decryptedBuffer[0], &decryptedSize);
                if (status != NO_ERROR || decryptedSize != static_cast<int>(sizeof(plaintext)) ||
                    std::memcmp(decryptedBuffer.data(), plaintext, sizeof(plaintext)) != 0)
                {
                    std::cout << "RunLegacyAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] Decrypt/mismatch status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::cout << "RunLegacyAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                          << "] round-trip via CCryptoApi" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunLegacyAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and round-tripped)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunLegacyAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunAesConfigurationDemoTest(void)
{
    try
    {
        const char* password = "AesDemoPass!2026";
        const int passwordSize = static_cast<int>(std::strlen(password));

        const char* text = "Pijamal\xC4\xB1 hasta ya\xC4\x9F\xC4\xB1z \xC5\x9Fof\xC3\xB6re \xC3\xA7" "abucak g\xC3\xBCvendi.";
        const int textSize = static_cast<int>(std::strlen(text));

        const AeadAlgorithm aeadAlgorithms[] =
        {
            AEAD_AES_128_GCM, AEAD_AES_192_GCM, AEAD_AES_256_GCM,
            AEAD_AES_128_CCM, AEAD_AES_192_CCM, AEAD_AES_256_CCM,
            AEAD_AES_128_EAX, AEAD_AES_192_EAX, AEAD_AES_256_EAX,
            AEAD_AES_128_SIV, AEAD_AES_256_SIV,
            AEAD_AES_128_GCM_SIV, AEAD_AES_256_GCM_SIV
        };

        const LegacySymmetricAlgorithm legacyAlgorithms[] =
        {
            LEGACY_AES_128_CBC, LEGACY_AES_192_CBC, LEGACY_AES_256_CBC,
            LEGACY_AES_128_CTR, LEGACY_AES_192_CTR, LEGACY_AES_256_CTR,
            LEGACY_AES_128_CFB, LEGACY_AES_192_CFB, LEGACY_AES_256_CFB,
            LEGACY_AES_128_OFB, LEGACY_AES_192_OFB, LEGACY_AES_256_OFB,
            LEGACY_AES_128_ECB, LEGACY_AES_192_ECB, LEGACY_AES_256_ECB
        };

        std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_CRYPTOPP);
        if (!factory)
        {
            std::cout << "RunAesConfigurationDemoTest: FAILED CreateProviderFactory" << std::endl;
            return UNEXPECTED_ERROR;
        }

        int failures = 0;
        int demonstratedCount = 0;

        for (std::size_t index = 0; index < sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]); ++index)
        {
            const AeadAlgorithm algorithm = aeadAlgorithms[index];
            const char* algorithmName = AeadAlgorithmName(algorithm);

            if (!factory->SupportsAeadAlgorithm(algorithm))
            {
                std::cout << "RunAesConfigurationDemoTest: SKIPPED [" << algorithmName << "] not supported by CryptoPP" << std::endl;
                continue;
            }

            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, algorithm);

            int requiredEncryptSize = 0;
            int status = cryptoApi.EncryptString(password, passwordSize, text, textSize,
                                                 0, nullptr, &requiredEncryptSize,
                                                 nullptr, nullptr);
            if (status != BUFFER_TOO_SMALL)
            {
                std::cout << "RunAesConfigurationDemoTest: FAILED [" << algorithmName << "] encrypt size query status=" << status << std::endl;
                ++failures;
                continue;
            }

            std::vector<unsigned char> encryptedData(requiredEncryptSize);
            int encryptedSize = 0;
            status = cryptoApi.EncryptString(password, passwordSize, text, textSize,
                                             requiredEncryptSize, &encryptedData[0], &encryptedSize,
                                             nullptr, nullptr);
            if (status != NO_ERROR)
            {
                std::cout << "RunAesConfigurationDemoTest: FAILED [" << algorithmName << "] EncryptString status=" << status << std::endl;
                ++failures;
                continue;
            }

            int requiredDecryptSize = 0;
            status = cryptoApi.DecryptString(password, passwordSize,
                                             &encryptedData[0], encryptedSize,
                                             0, nullptr, &requiredDecryptSize,
                                             nullptr, nullptr);
            if (status != BUFFER_TOO_SMALL)
            {
                std::cout << "RunAesConfigurationDemoTest: FAILED [" << algorithmName << "] decrypt size query status=" << status << std::endl;
                ++failures;
                continue;
            }

            std::vector<char> decryptedText(requiredDecryptSize);
            int decryptedSize = 0;
            status = cryptoApi.DecryptString(password, passwordSize,
                                             &encryptedData[0], encryptedSize,
                                             requiredDecryptSize,
                                             decryptedText.empty() ? nullptr : &decryptedText[0], &decryptedSize,
                                             nullptr, nullptr);
            if (status != NO_ERROR || decryptedSize != textSize ||
                std::memcmp(&decryptedText[0], text, static_cast<std::size_t>(textSize)) != 0)
            {
                std::cout << "RunAesConfigurationDemoTest: FAILED [" << algorithmName << "] Decrypt/mismatch status=" << status << std::endl;
                ++failures;
                continue;
            }

            ++demonstratedCount;
            std::cout << "RunAesConfigurationDemoTest: PASSED [" << algorithmName << "] round-trip (" << encryptedSize << " bytes)" << std::endl;
        }

        for (std::size_t index = 0; index < sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]); ++index)
        {
            const LegacySymmetricAlgorithm algorithm = legacyAlgorithms[index];
            const char* algorithmName = LegacyAlgorithmName(algorithm);

            if (!factory->SupportsLegacyAlgorithm(algorithm))
            {
                std::cout << "RunAesConfigurationDemoTest: SKIPPED [" << algorithmName << "] not supported by CryptoPP" << std::endl;
                continue;
            }

            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, algorithm);

            const unsigned char* textBytes = reinterpret_cast<const unsigned char*>(text);

            int requiredEncryptSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                                       textBytes, textSize,
                                                       0, nullptr, &requiredEncryptSize);
            if (status != BUFFER_TOO_SMALL)
            {
                std::cout << "RunAesConfigurationDemoTest: FAILED [" << algorithmName << "] encrypt size query status=" << status << std::endl;
                ++failures;
                continue;
            }

            std::vector<unsigned char> encryptedBuffer(requiredEncryptSize);
            int encryptedSize = 0;
            status = cryptoApi.EncryptLegacyBuffer(password, passwordSize,
                                                   textBytes, textSize,
                                                   requiredEncryptSize, &encryptedBuffer[0], &encryptedSize);
            if (status != NO_ERROR)
            {
                std::cout << "RunAesConfigurationDemoTest: FAILED [" << algorithmName << "] EncryptLegacyBuffer status=" << status << std::endl;
                ++failures;
                continue;
            }

            int requiredDecryptSize = 0;
            status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                                   &encryptedBuffer[0], encryptedSize,
                                                   0, nullptr, &requiredDecryptSize);
            if (status != BUFFER_TOO_SMALL)
            {
                std::cout << "RunAesConfigurationDemoTest: FAILED [" << algorithmName << "] decrypt size query status=" << status << std::endl;
                ++failures;
                continue;
            }

            std::vector<unsigned char> decryptedBuffer(requiredDecryptSize);
            int decryptedSize = 0;
            status = cryptoApi.DecryptLegacyBuffer(password, passwordSize,
                                                   &encryptedBuffer[0], encryptedSize,
                                                   requiredDecryptSize, decryptedBuffer.empty() ? nullptr : &decryptedBuffer[0], &decryptedSize);
            if (status != NO_ERROR || decryptedSize != textSize ||
                std::memcmp(decryptedBuffer.data(), textBytes, static_cast<std::size_t>(textSize)) != 0)
            {
                std::cout << "RunAesConfigurationDemoTest: FAILED [" << algorithmName << "] Decrypt/mismatch status=" << status << std::endl;
                ++failures;
                continue;
            }

            ++demonstratedCount;
            std::cout << "RunAesConfigurationDemoTest: PASSED [" << algorithmName << "] round-trip (" << encryptedSize << " bytes)" << std::endl;
        }

        if (failures == 0)
        {
            std::cout << "RunAesConfigurationDemoTest: PASSED (" << demonstratedCount << " AES key-size/mode combinations demonstrated)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunAesConfigurationDemoTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncodingUtilsTest(void)
{
    try
    {
        int failures = 0;

        // Hex: "af" byte should round-trip and prove upper/lower digit selection actually differs.
        {
            const unsigned char bytes[] = { 0x00, 0xAF, 0xFF, 0x10 };
            const int byteCount = static_cast<int>(sizeof(bytes));

            int requiredLowerSize = 0;
            int status = CUtils::HexEncode(bytes, byteCount, false, 0, nullptr, &requiredLowerSize);
            if (status != BUFFER_TOO_SMALL || requiredLowerSize != byteCount * 2)
            {
                std::cout << "RunEncodingUtilsTest: FAILED HexEncode lower-case size query status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::vector<char> lowerHex(requiredLowerSize);
                int lowerSize = 0;
                status = CUtils::HexEncode(bytes, byteCount, false, requiredLowerSize, &lowerHex[0], &lowerSize);
                const std::string lowerText(lowerHex.begin(), lowerHex.end());
                if (status != NO_ERROR || lowerText != "00afff10")
                {
                    std::cout << "RunEncodingUtilsTest: FAILED HexEncode lower-case content status=" << status
                              << " text=" << lowerText << std::endl;
                    ++failures;
                }
                else
                {
                    std::cout << "RunEncodingUtilsTest: PASSED HexEncode lower-case (" << lowerText << ")" << std::endl;
                }
            }

            int requiredUpperSize = 0;
            status = CUtils::HexEncode(bytes, byteCount, true, 0, nullptr, &requiredUpperSize);
            std::vector<char> upperHex(requiredUpperSize);
            int upperSize = 0;
            status = CUtils::HexEncode(bytes, byteCount, true, requiredUpperSize, &upperHex[0], &upperSize);
            const std::string upperText(upperHex.begin(), upperHex.end());
            if (status != NO_ERROR || upperText != "00AFFF10")
            {
                std::cout << "RunEncodingUtilsTest: FAILED HexEncode upper-case content status=" << status
                          << " text=" << upperText << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunEncodingUtilsTest: PASSED HexEncode upper-case (" << upperText << ")" << std::endl;
            }

            int requiredDecodeSize = 0;
            status = CUtils::HexDecode(upperText.c_str(), static_cast<int>(upperText.size()), 0, nullptr, &requiredDecodeSize);
            if (status != BUFFER_TOO_SMALL || requiredDecodeSize != byteCount)
            {
                std::cout << "RunEncodingUtilsTest: FAILED HexDecode size query status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::vector<unsigned char> decoded(requiredDecodeSize);
                status = CUtils::HexDecode(upperText.c_str(), static_cast<int>(upperText.size()), requiredDecodeSize, &decoded[0], &requiredDecodeSize);
                if (status != NO_ERROR || std::memcmp(&decoded[0], bytes, byteCount) != 0)
                {
                    std::cout << "RunEncodingUtilsTest: FAILED HexDecode mismatch status=" << status << std::endl;
                    ++failures;
                }
                else
                {
                    std::cout << "RunEncodingUtilsTest: PASSED HexDecode round-trip" << std::endl;
                }
            }

            // Malformed input: odd length and a non-hex character must both be rejected.
            int dummySize = 0;
            if (CUtils::HexDecode("abc", 3, 0, nullptr, &dummySize) != INVALID_ARGUMENT)
            {
                std::cout << "RunEncodingUtilsTest: FAILED HexDecode odd-length not rejected" << std::endl;
                ++failures;
            }

            unsigned char oneByte = 0;
            if (CUtils::HexDecode("zz", 2, 1, &oneByte, &dummySize) != INVALID_DATA)
            {
                std::cout << "RunEncodingUtilsTest: FAILED HexDecode non-hex character not rejected" << std::endl;
                ++failures;
            }

            if (failures == 0)
            {
                std::cout << "RunEncodingUtilsTest: PASSED HexDecode malformed-input rejection" << std::endl;
            }
        }

        // Base64: the classic "Man"/"Ma"/"M" cases exercise zero/one/two bytes of padding.
        {
            struct Base64Case
            {
                const char* text;
                const char* expectedBase64;
            };

            const Base64Case base64Cases[] =
            {
                { "Man", "TWFu" },
                { "Ma",  "TWE=" },
                { "M",   "TQ==" },
                { "",    "" }
            };

            for (std::size_t index = 0; index < sizeof(base64Cases) / sizeof(base64Cases[0]); ++index)
            {
                const char* text = base64Cases[index].text;
                const char* expectedBase64 = base64Cases[index].expectedBase64;
                const int textSize = static_cast<int>(std::strlen(text));
                const unsigned char* textBytes = reinterpret_cast<const unsigned char*>(text);

                int requiredEncodeSize = 0;
                int status = CUtils::Base64Encode(textBytes, textSize, 0, nullptr, &requiredEncodeSize);
                if (requiredEncodeSize == 0)
                {
                    if (std::strlen(expectedBase64) != 0)
                    {
                        std::cout << "RunEncodingUtilsTest: FAILED Base64Encode \"" << text << "\" expected non-empty size" << std::endl;
                        ++failures;
                    }
                    else
                    {
                        std::cout << "RunEncodingUtilsTest: PASSED Base64Encode \"\" -> \"\"" << std::endl;
                    }
                    continue;
                }

                if (status != BUFFER_TOO_SMALL)
                {
                    std::cout << "RunEncodingUtilsTest: FAILED Base64Encode \"" << text << "\" size query status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<char> encoded(requiredEncodeSize);
                int encodedSize = 0;
                status = CUtils::Base64Encode(textBytes, textSize, requiredEncodeSize, &encoded[0], &encodedSize);
                const std::string encodedText(encoded.begin(), encoded.end());
                if (status != NO_ERROR || encodedText != expectedBase64)
                {
                    std::cout << "RunEncodingUtilsTest: FAILED Base64Encode \"" << text << "\" -> \"" << encodedText
                              << "\" expected \"" << expectedBase64 << "\"" << std::endl;
                    ++failures;
                    continue;
                }

                std::cout << "RunEncodingUtilsTest: PASSED Base64Encode \"" << text << "\" -> \"" << encodedText << "\"" << std::endl;

                int requiredDecodeSize = 0;
                status = CUtils::Base64Decode(encodedText.c_str(), static_cast<int>(encodedText.size()), 0, nullptr, &requiredDecodeSize);
                if (status != BUFFER_TOO_SMALL || requiredDecodeSize != textSize)
                {
                    std::cout << "RunEncodingUtilsTest: FAILED Base64Decode \"" << encodedText << "\" size query status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> decoded(requiredDecodeSize);
                int decodedSize = 0;
                status = CUtils::Base64Decode(encodedText.c_str(), static_cast<int>(encodedText.size()),
                                              requiredDecodeSize, decoded.empty() ? nullptr : &decoded[0], &decodedSize);
                if (status != NO_ERROR || decodedSize != textSize ||
                    (textSize > 0 && std::memcmp(&decoded[0], textBytes, static_cast<std::size_t>(textSize)) != 0))
                {
                    std::cout << "RunEncodingUtilsTest: FAILED Base64Decode \"" << encodedText << "\" mismatch status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::cout << "RunEncodingUtilsTest: PASSED Base64Decode \"" << encodedText << "\" -> \"" << text << "\"" << std::endl;
            }

            // Malformed input: length not a multiple of 4, and a character outside the alphabet.
            int dummySize = 0;
            if (CUtils::Base64Decode("abc", 3, 0, nullptr, &dummySize) != INVALID_ARGUMENT)
            {
                std::cout << "RunEncodingUtilsTest: FAILED Base64Decode non-multiple-of-4 length not rejected" << std::endl;
                ++failures;
            }

            unsigned char threeBytes[3] = { 0, 0, 0 };
            if (CUtils::Base64Decode("T!WFu", 5, 0, nullptr, &dummySize) != INVALID_ARGUMENT)
            {
                std::cout << "RunEncodingUtilsTest: FAILED Base64Decode non-multiple-of-4 (5 chars) not rejected" << std::endl;
                ++failures;
            }

            if (CUtils::Base64Decode("T!Fu", 4, 3, threeBytes, &dummySize) != INVALID_DATA)
            {
                std::cout << "RunEncodingUtilsTest: FAILED Base64Decode invalid character not rejected" << std::endl;
                ++failures;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunEncodingUtilsTest: PASSED (all Hex/Base64 encode/decode checks)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunEncodingUtilsTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPaddingUtilsTest(void)
{
    try
    {
        const unsigned int blockSize = 16;
        int failures = 0;

        // Known PKCS7 vector: 5-byte "HELLO" padded to one 16-byte block with 11 bytes of 0x0B.
        {
            const unsigned char input[] = { 'H', 'E', 'L', 'L', 'O' };
            const unsigned char expected[16] =
            {
                'H', 'E', 'L', 'L', 'O',
                0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B
            };

            unsigned char padded[16];
            int paddedSize = 0;
            int status = CUtils::Pad(PADDING_PKCS7, blockSize, input, static_cast<int>(sizeof(input)), sizeof(padded), padded, &paddedSize);
            if (status != NO_ERROR || paddedSize != 16 || std::memcmp(padded, expected, 16) != 0)
            {
                std::cout << "RunPaddingUtilsTest: FAILED PKCS7 known vector status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunPaddingUtilsTest: PASSED PKCS7 known vector" << std::endl;
            }
        }

        // Round-trip: every padding-adding scheme, over a misaligned and an already-aligned input.
        // Avoid trailing 0x00 bytes in the plaintext for the round-trip check since ZeroPadding
        // cannot distinguish real trailing zero bytes from its own padding (documented caveat, not
        // tested as a failure here).
        {
            struct SchemeCase { PaddingScheme scheme; };
            const SchemeCase schemeCases[] =
            {
                { PADDING_PKCS7 }, { PADDING_PKCS5 }, { PADDING_ANSI_X923 },
                { PADDING_ISO_10126 }, { PADDING_ISO_97971 }, { PADDING_ZERO }
            };

            const unsigned char misaligned[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x2A };
            const unsigned char aligned[]    = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x2A };

            struct InputCase { const unsigned char* data; int size; const char* label; };
            const InputCase inputCases[] =
            {
                { misaligned, static_cast<int>(sizeof(misaligned)), "misaligned" },
                { aligned,    static_cast<int>(sizeof(aligned)),    "aligned" }
            };

            for (std::size_t schemeIndex = 0; schemeIndex < sizeof(schemeCases) / sizeof(schemeCases[0]); ++schemeIndex)
            {
                const PaddingScheme scheme = schemeCases[schemeIndex].scheme;
                const char* schemeName = PaddingSchemeName(scheme);

                for (std::size_t inputIndex = 0; inputIndex < sizeof(inputCases) / sizeof(inputCases[0]); ++inputIndex)
                {
                    const unsigned char* data = inputCases[inputIndex].data;
                    const int dataSize = inputCases[inputIndex].size;
                    const char* inputLabel = inputCases[inputIndex].label;

                    int requiredPadSize = 0;
                    int status = CUtils::Pad(scheme, blockSize, data, dataSize, 0, nullptr, &requiredPadSize);
                    if (status != BUFFER_TOO_SMALL)
                    {
                        std::cout << "RunPaddingUtilsTest: FAILED [" << schemeName << "/" << inputLabel << "] Pad size query status=" << status << std::endl;
                        ++failures;
                        continue;
                    }

                    std::vector<unsigned char> padded(requiredPadSize);
                    int paddedSize = 0;
                    status = CUtils::Pad(scheme, blockSize, data, dataSize, requiredPadSize, padded.empty() ? nullptr : &padded[0], &paddedSize);
                    if (status != NO_ERROR || paddedSize % static_cast<int>(blockSize) != 0)
                    {
                        std::cout << "RunPaddingUtilsTest: FAILED [" << schemeName << "/" << inputLabel << "] Pad status=" << status << std::endl;
                        ++failures;
                        continue;
                    }

                    int requiredUnpadSize = 0;
                    status = CUtils::Unpad(scheme, blockSize, &padded[0], paddedSize, 0, nullptr, &requiredUnpadSize);
                    if (status != BUFFER_TOO_SMALL)
                    {
                        std::cout << "RunPaddingUtilsTest: FAILED [" << schemeName << "/" << inputLabel << "] Unpad size query status=" << status << std::endl;
                        ++failures;
                        continue;
                    }

                    std::vector<unsigned char> unpadded(requiredUnpadSize);
                    int unpaddedSize = 0;
                    status = CUtils::Unpad(scheme, blockSize, &padded[0], paddedSize, requiredUnpadSize, unpadded.empty() ? nullptr : &unpadded[0], &unpaddedSize);
                    if (status != NO_ERROR || unpaddedSize != dataSize || std::memcmp(&unpadded[0], data, static_cast<std::size_t>(dataSize)) != 0)
                    {
                        std::cout << "RunPaddingUtilsTest: FAILED [" << schemeName << "/" << inputLabel << "] Unpad/mismatch status=" << status << std::endl;
                        ++failures;
                        continue;
                    }

                    std::cout << "RunPaddingUtilsTest: PASSED [" << schemeName << "/" << inputLabel << "] round-trip (" << paddedSize << " bytes)" << std::endl;
                }
            }
        }

        // PADDING_NONE: aligned input passes through unchanged; misaligned input is rejected.
        {
            const unsigned char aligned[16] = { 0 };
            int requiredSize = 0;
            int status = CUtils::Pad(PADDING_NONE, blockSize, aligned, static_cast<int>(sizeof(aligned)), 0, nullptr, &requiredSize);
            if (status != BUFFER_TOO_SMALL || requiredSize != static_cast<int>(sizeof(aligned)))
            {
                std::cout << "RunPaddingUtilsTest: FAILED NoPadding aligned size query status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunPaddingUtilsTest: PASSED NoPadding aligned size query" << std::endl;
            }

            const unsigned char misaligned[5] = { 0 };
            if (CUtils::Pad(PADDING_NONE, blockSize, misaligned, static_cast<int>(sizeof(misaligned)), 0, nullptr, &requiredSize) != INVALID_ARGUMENT)
            {
                std::cout << "RunPaddingUtilsTest: FAILED NoPadding misaligned input not rejected" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunPaddingUtilsTest: PASSED NoPadding misaligned input rejected" << std::endl;
            }

            if (CUtils::Unpad(PADDING_NONE, blockSize, misaligned, static_cast<int>(sizeof(misaligned)), 0, nullptr, &requiredSize) != INVALID_ARGUMENT)
            {
                std::cout << "RunPaddingUtilsTest: FAILED NoPadding Unpad misaligned input not rejected" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunPaddingUtilsTest: PASSED NoPadding Unpad misaligned input rejected" << std::endl;
            }
        }

        // Malformed padding must be rejected by Unpad.
        {
            unsigned char dummyOutput[16];
            int dummySize = 0;

            unsigned char zeroPadByte[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0x00 };
            if (CUtils::Unpad(PADDING_PKCS7, blockSize, zeroPadByte, 16, sizeof(dummyOutput), dummyOutput, &dummySize) != INVALID_DATA)
            {
                std::cout << "RunPaddingUtilsTest: FAILED PKCS7 zero pad-length byte not rejected" << std::endl;
                ++failures;
            }

            unsigned char tooLargePadByte[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0xFF };
            if (CUtils::Unpad(PADDING_PKCS7, blockSize, tooLargePadByte, 16, sizeof(dummyOutput), dummyOutput, &dummySize) != INVALID_DATA)
            {
                std::cout << "RunPaddingUtilsTest: FAILED PKCS7 out-of-range pad-length byte not rejected" << std::endl;
                ++failures;
            }

            unsigned char inconsistentPadBytes[16] = { 1,2,3,4,5,6,7,8,9,10,11,12, 0x00, 0x04, 0x04, 0x04 };
            if (CUtils::Unpad(PADDING_PKCS7, blockSize, inconsistentPadBytes, 16, sizeof(dummyOutput), dummyOutput, &dummySize) != INVALID_DATA)
            {
                std::cout << "RunPaddingUtilsTest: FAILED PKCS7 inconsistent pad bytes not rejected" << std::endl;
                ++failures;
            }

            unsigned char ansiInconsistent[16] = { 1,2,3,4,5,6,7,8,9,10,11,12, 0x01, 0x00, 0x00, 0x04 };
            if (CUtils::Unpad(PADDING_ANSI_X923, blockSize, ansiInconsistent, 16, sizeof(dummyOutput), dummyOutput, &dummySize) != INVALID_DATA)
            {
                std::cout << "RunPaddingUtilsTest: FAILED AnsiX923 inconsistent pad bytes not rejected" << std::endl;
                ++failures;
            }

            unsigned char noIso97971Marker[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0x00 };
            if (CUtils::Unpad(PADDING_ISO_97971, blockSize, noIso97971Marker, 16, sizeof(dummyOutput), dummyOutput, &dummySize) != INVALID_DATA)
            {
                std::cout << "RunPaddingUtilsTest: FAILED Iso97971 missing 0x80 marker not rejected" << std::endl;
                ++failures;
            }

            if (failures == 0)
            {
                std::cout << "RunPaddingUtilsTest: PASSED malformed-padding rejection" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunPaddingUtilsTest: PASSED (all Pad/Unpad checks)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunPaddingUtilsTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptHexBase64CompositionTest(void)
{
    try
    {
        CCryptoApi cryptoApi;

        const char* password = "MyPassword123!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        const char* text = "Merhaba d\xC3\xBCnya";
        const int textSize = static_cast<int>(std::strlen(text));

        int failures = 0;

        // 1) Encrypt -> raw ciphertext bytes.
        int requiredCipherSize = 0;
        int status = cryptoApi.EncryptString(password, passwordSize, text, textSize,
                                             0, nullptr, &requiredCipherSize,
                                             nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunEncryptHexBase64CompositionTest: FAILED encrypt size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> cipherBytes(requiredCipherSize);
        int cipherSize = 0;
        status = cryptoApi.EncryptString(password, passwordSize, text, textSize,
                                         requiredCipherSize, &cipherBytes[0], &cipherSize,
                                         nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunEncryptHexBase64CompositionTest: FAILED EncryptString status=" << status << std::endl;
            return status;
        }

        // 2a) Hex path: raw ciphertext -> Hex text -> raw ciphertext -> Decrypt.
        {
            int requiredHexSize = 0;
            status = CUtils::HexEncode(&cipherBytes[0], cipherSize, true, 0, nullptr, &requiredHexSize);
            if (status != BUFFER_TOO_SMALL)
            {
                std::cout << "RunEncryptHexBase64CompositionTest: FAILED HexEncode size query status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::vector<char> hexText(requiredHexSize);
                int hexSize = 0;
                status = CUtils::HexEncode(&cipherBytes[0], cipherSize, true, requiredHexSize, &hexText[0], &hexSize);
                const std::string hexString(hexText.begin(), hexText.end());

                int requiredDecodedCipherSize = 0;
                status = CUtils::HexDecode(hexString.c_str(), static_cast<int>(hexString.size()), 0, nullptr, &requiredDecodedCipherSize);
                if (status != BUFFER_TOO_SMALL || requiredDecodedCipherSize != cipherSize)
                {
                    std::cout << "RunEncryptHexBase64CompositionTest: FAILED HexDecode size query status=" << status << std::endl;
                    ++failures;
                }
                else
                {
                    std::vector<unsigned char> decodedCipherBytes(requiredDecodedCipherSize);
                    int decodedCipherSize = 0;
                    status = CUtils::HexDecode(hexString.c_str(), static_cast<int>(hexString.size()),
                                               requiredDecodedCipherSize, &decodedCipherBytes[0], &decodedCipherSize);

                    int requiredTextSize = 0;
                    status = cryptoApi.DecryptString(password, passwordSize, &decodedCipherBytes[0], decodedCipherSize,
                                                     0, nullptr, &requiredTextSize,
                                                     nullptr, nullptr);
                    if (status != BUFFER_TOO_SMALL)
                    {
                        std::cout << "RunEncryptHexBase64CompositionTest: FAILED Hex-path decrypt size query status=" << status << std::endl;
                        ++failures;
                    }
                    else
                    {
                        std::vector<char> decryptedText(requiredTextSize);
                        int decryptedSize = 0;
                        status = cryptoApi.DecryptString(password, passwordSize, &decodedCipherBytes[0], decodedCipherSize,
                                                         requiredTextSize, &decryptedText[0], &decryptedSize,
                                                         nullptr, nullptr);
                        if (status != NO_ERROR || decryptedSize != textSize ||
                            std::memcmp(&decryptedText[0], text, static_cast<std::size_t>(textSize)) != 0)
                        {
                            std::cout << "RunEncryptHexBase64CompositionTest: FAILED Hex-path decrypt/mismatch status=" << status << std::endl;
                            ++failures;
                        }
                        else
                        {
                            std::cout << "RunEncryptHexBase64CompositionTest: PASSED Hex path (" << hexString << ")" << std::endl;
                        }
                    }
                }
            }
        }

        // 2b) Base64 path: raw ciphertext -> Base64 text -> raw ciphertext -> Decrypt.
        {
            int requiredBase64Size = 0;
            status = CUtils::Base64Encode(&cipherBytes[0], cipherSize, 0, nullptr, &requiredBase64Size);
            if (status != BUFFER_TOO_SMALL)
            {
                std::cout << "RunEncryptHexBase64CompositionTest: FAILED Base64Encode size query status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::vector<char> base64Text(requiredBase64Size);
                int base64Size = 0;
                status = CUtils::Base64Encode(&cipherBytes[0], cipherSize, requiredBase64Size, &base64Text[0], &base64Size);
                const std::string base64String(base64Text.begin(), base64Text.end());

                int requiredDecodedCipherSize = 0;
                status = CUtils::Base64Decode(base64String.c_str(), static_cast<int>(base64String.size()), 0, nullptr, &requiredDecodedCipherSize);
                if (status != BUFFER_TOO_SMALL || requiredDecodedCipherSize != cipherSize)
                {
                    std::cout << "RunEncryptHexBase64CompositionTest: FAILED Base64Decode size query status=" << status << std::endl;
                    ++failures;
                }
                else
                {
                    std::vector<unsigned char> decodedCipherBytes(requiredDecodedCipherSize);
                    int decodedCipherSize = 0;
                    status = CUtils::Base64Decode(base64String.c_str(), static_cast<int>(base64String.size()),
                                                  requiredDecodedCipherSize, &decodedCipherBytes[0], &decodedCipherSize);

                    int requiredTextSize = 0;
                    status = cryptoApi.DecryptString(password, passwordSize, &decodedCipherBytes[0], decodedCipherSize,
                                                     0, nullptr, &requiredTextSize,
                                                     nullptr, nullptr);
                    if (status != BUFFER_TOO_SMALL)
                    {
                        std::cout << "RunEncryptHexBase64CompositionTest: FAILED Base64-path decrypt size query status=" << status << std::endl;
                        ++failures;
                    }
                    else
                    {
                        std::vector<char> decryptedText(requiredTextSize);
                        int decryptedSize = 0;
                        status = cryptoApi.DecryptString(password, passwordSize, &decodedCipherBytes[0], decodedCipherSize,
                                                         requiredTextSize, &decryptedText[0], &decryptedSize,
                                                         nullptr, nullptr);
                        if (status != NO_ERROR || decryptedSize != textSize ||
                            std::memcmp(&decryptedText[0], text, static_cast<std::size_t>(textSize)) != 0)
                        {
                            std::cout << "RunEncryptHexBase64CompositionTest: FAILED Base64-path decrypt/mismatch status=" << status << std::endl;
                            ++failures;
                        }
                        else
                        {
                            std::cout << "RunEncryptHexBase64CompositionTest: PASSED Base64 path (" << base64String << ")" << std::endl;
                        }
                    }
                }
            }
        }

        if (failures == 0)
        {
            std::cout << "RunEncryptHexBase64CompositionTest: PASSED (Hex and Base64 composition round-trips)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunEncryptHexBase64CompositionTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptFileHexBase64CompositionTest(void)
{
    try
    {
        const char* password = "MyFilePassword123!";

        const char* inputFilePath          = "cryptoapi_filehexb64_in.bin";
        const char* encryptedFilePath      = "cryptoapi_filehexb64_enc.bin";
        const char* hexTextFilePath        = "cryptoapi_filehexb64_enc.hex";
        const char* hexDecodedFilePath     = "cryptoapi_filehexb64_fromhex.bin";
        const char* hexDecryptedFilePath   = "cryptoapi_filehexb64_fromhex_out.bin";
        const char* base64TextFilePath     = "cryptoapi_filehexb64_enc.b64";
        const char* base64DecodedFilePath  = "cryptoapi_filehexb64_fromb64.bin";
        const char* base64DecryptedFilePath = "cryptoapi_filehexb64_fromb64_out.bin";

        const char* allPaths[] =
        {
            inputFilePath, encryptedFilePath, hexTextFilePath, hexDecodedFilePath, hexDecryptedFilePath,
            base64TextFilePath, base64DecodedFilePath, base64DecryptedFilePath
        };

        struct Cleanup
        {
            const char** paths;
            std::size_t count;
            ~Cleanup() { for (std::size_t index = 0; index < count; ++index) { std::remove(paths[index]); } }
        } cleanup = { allPaths, sizeof(allPaths) / sizeof(allPaths[0]) };

        std::vector<unsigned char> inputData(4096);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunEncryptFileHexBase64CompositionTest: FAILED to write input file" << std::endl;
            return FILE_IO_ERROR;
        }

        CCryptoApi cryptoApi;

        // 1) EncryptFile -> raw ciphertext bytes on disk.
        int status = cryptoApi.EncryptFile(password, inputFilePath, encryptedFilePath, nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunEncryptFileHexBase64CompositionTest: FAILED EncryptFile status=" << status << std::endl;
            return status;
        }

        std::vector<unsigned char> encryptedBytes;
        if (!ReadTesterFile(encryptedFilePath, encryptedBytes))
        {
            std::cout << "RunEncryptFileHexBase64CompositionTest: FAILED to read encrypted file" << std::endl;
            return FILE_IO_ERROR;
        }

        int failures = 0;

        // 2a) Hex path: encrypted file bytes -> Hex text file -> back to bytes -> DecryptFile.
        {
            int requiredHexSize = 0;
            CUtils::HexEncode(&encryptedBytes[0], static_cast<int>(encryptedBytes.size()), true, 0, nullptr, &requiredHexSize);

            std::vector<char> hexText(requiredHexSize);
            int hexSize = 0;
            CUtils::HexEncode(&encryptedBytes[0], static_cast<int>(encryptedBytes.size()), true, requiredHexSize, &hexText[0], &hexSize);

            std::ofstream hexFileStream(hexTextFilePath, std::ios::binary);
            hexFileStream.write(&hexText[0], static_cast<std::streamsize>(hexText.size()));
            hexFileStream.close();

            std::ifstream hexReadStream(hexTextFilePath, std::ios::binary);
            const std::string hexFromFile((std::istreambuf_iterator<char>(hexReadStream)), std::istreambuf_iterator<char>());

            int requiredCipherSize = 0;
            CUtils::HexDecode(hexFromFile.c_str(), static_cast<int>(hexFromFile.size()), 0, nullptr, &requiredCipherSize);

            std::vector<unsigned char> decodedCipherBytes(requiredCipherSize);
            int decodedCipherSize = 0;
            CUtils::HexDecode(hexFromFile.c_str(), static_cast<int>(hexFromFile.size()),
                              requiredCipherSize, &decodedCipherBytes[0], &decodedCipherSize);

            if (!WriteTesterFile(hexDecodedFilePath, decodedCipherBytes))
            {
                std::cout << "RunEncryptFileHexBase64CompositionTest: FAILED to write hex-decoded binary file" << std::endl;
                ++failures;
            }
            else
            {
                status = cryptoApi.DecryptFile(password, hexDecodedFilePath, hexDecryptedFilePath, nullptr, nullptr);

                std::vector<unsigned char> outputData;
                if (status != NO_ERROR || !ReadTesterFile(hexDecryptedFilePath, outputData) ||
                    outputData.size() != inputData.size() ||
                    (!inputData.empty() && std::memcmp(&outputData[0], &inputData[0], inputData.size()) != 0))
                {
                    std::cout << "RunEncryptFileHexBase64CompositionTest: FAILED Hex-path DecryptFile/mismatch status=" << status << std::endl;
                    ++failures;
                }
                else
                {
                    std::cout << "RunEncryptFileHexBase64CompositionTest: PASSED Hex path (" << hexDecodedFilePath << ")" << std::endl;
                }
            }
        }

        // 2b) Base64 path: encrypted file bytes -> Base64 text file -> back to bytes -> DecryptFile.
        {
            int requiredBase64Size = 0;
            CUtils::Base64Encode(&encryptedBytes[0], static_cast<int>(encryptedBytes.size()), 0, nullptr, &requiredBase64Size);

            std::vector<char> base64Text(requiredBase64Size);
            int base64Size = 0;
            CUtils::Base64Encode(&encryptedBytes[0], static_cast<int>(encryptedBytes.size()), requiredBase64Size, &base64Text[0], &base64Size);

            std::ofstream base64FileStream(base64TextFilePath, std::ios::binary);
            base64FileStream.write(&base64Text[0], static_cast<std::streamsize>(base64Text.size()));
            base64FileStream.close();

            std::ifstream base64ReadStream(base64TextFilePath, std::ios::binary);
            const std::string base64FromFile((std::istreambuf_iterator<char>(base64ReadStream)), std::istreambuf_iterator<char>());

            int requiredCipherSize = 0;
            CUtils::Base64Decode(base64FromFile.c_str(), static_cast<int>(base64FromFile.size()), 0, nullptr, &requiredCipherSize);

            std::vector<unsigned char> decodedCipherBytes(requiredCipherSize);
            int decodedCipherSize = 0;
            CUtils::Base64Decode(base64FromFile.c_str(), static_cast<int>(base64FromFile.size()),
                                 requiredCipherSize, &decodedCipherBytes[0], &decodedCipherSize);

            if (!WriteTesterFile(base64DecodedFilePath, decodedCipherBytes))
            {
                std::cout << "RunEncryptFileHexBase64CompositionTest: FAILED to write base64-decoded binary file" << std::endl;
                ++failures;
            }
            else
            {
                status = cryptoApi.DecryptFile(password, base64DecodedFilePath, base64DecryptedFilePath, nullptr, nullptr);

                std::vector<unsigned char> outputData;
                if (status != NO_ERROR || !ReadTesterFile(base64DecryptedFilePath, outputData) ||
                    outputData.size() != inputData.size() ||
                    (!inputData.empty() && std::memcmp(&outputData[0], &inputData[0], inputData.size()) != 0))
                {
                    std::cout << "RunEncryptFileHexBase64CompositionTest: FAILED Base64-path DecryptFile/mismatch status=" << status << std::endl;
                    ++failures;
                }
                else
                {
                    std::cout << "RunEncryptFileHexBase64CompositionTest: PASSED Base64 path (" << base64DecodedFilePath << ")" << std::endl;
                }
            }
        }

        if (failures == 0)
        {
            std::cout << "RunEncryptFileHexBase64CompositionTest: PASSED (Hex and Base64 file composition round-trips)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunEncryptFileHexBase64CompositionTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashHexBase64CompositionTest(void)
{
    try
    {
        const char* text = "Pijamal\xC4\xB1 hasta ya\xC4\x9F\xC4\xB1z \xC5\x9Fof\xC3\xB6re \xC3\xA7" "abucak g\xC3\xBCvendi.";
        const int textSize = static_cast<int>(std::strlen(text));

        CCryptoApi cryptoApi;

        int requiredDigestSize = 0;
        int status = cryptoApi.ComputeHashString(text, textSize, 0, nullptr, &requiredDigestSize, nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunHashHexBase64CompositionTest: FAILED hash size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> digest(requiredDigestSize);
        int digestSize = 0;
        status = cryptoApi.ComputeHashString(text, textSize, requiredDigestSize, &digest[0], &digestSize, nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunHashHexBase64CompositionTest: FAILED ComputeHashString status=" << status << std::endl;
            return status;
        }

        int failures = 0;

        // Hex path: digest -> Hex text -> back to digest bytes.
        {
            int requiredHexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, true, 0, nullptr, &requiredHexSize);
            std::vector<char> hexText(requiredHexSize);
            int hexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, true, requiredHexSize, &hexText[0], &hexSize);
            const std::string hexString(hexText.begin(), hexText.end());

            int requiredDecodedSize = 0;
            CUtils::HexDecode(hexString.c_str(), static_cast<int>(hexString.size()), 0, nullptr, &requiredDecodedSize);
            std::vector<unsigned char> decoded(requiredDecodedSize);
            int decodedSize = 0;
            CUtils::HexDecode(hexString.c_str(), static_cast<int>(hexString.size()), requiredDecodedSize, &decoded[0], &decodedSize);

            if (decodedSize != digestSize || std::memcmp(&decoded[0], &digest[0], digestSize) != 0)
            {
                std::cout << "RunHashHexBase64CompositionTest: FAILED Hex path mismatch" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunHashHexBase64CompositionTest: PASSED Hex path (" << hexString << ")" << std::endl;
            }
        }

        // Base64 path: digest -> Base64 text -> back to digest bytes.
        {
            int requiredBase64Size = 0;
            CUtils::Base64Encode(&digest[0], digestSize, 0, nullptr, &requiredBase64Size);
            std::vector<char> base64Text(requiredBase64Size);
            int base64Size = 0;
            CUtils::Base64Encode(&digest[0], digestSize, requiredBase64Size, &base64Text[0], &base64Size);
            const std::string base64String(base64Text.begin(), base64Text.end());

            int requiredDecodedSize = 0;
            CUtils::Base64Decode(base64String.c_str(), static_cast<int>(base64String.size()), 0, nullptr, &requiredDecodedSize);
            std::vector<unsigned char> decoded(requiredDecodedSize);
            int decodedSize = 0;
            CUtils::Base64Decode(base64String.c_str(), static_cast<int>(base64String.size()), requiredDecodedSize, &decoded[0], &decodedSize);

            if (decodedSize != digestSize || std::memcmp(&decoded[0], &digest[0], digestSize) != 0)
            {
                std::cout << "RunHashHexBase64CompositionTest: FAILED Base64 path mismatch" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunHashHexBase64CompositionTest: PASSED Base64 path (" << base64String << ")" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunHashHexBase64CompositionTest: PASSED (Hex and Base64 digest composition round-trips)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunHashHexBase64CompositionTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashFileHexBase64CompositionTest(void)
{
    try
    {
        const char* inputFilePath = "cryptoapi_hashfilehexb64_in.bin";
        const char* hexTextFilePath = "cryptoapi_hashfilehexb64.hex";
        const char* base64TextFilePath = "cryptoapi_hashfilehexb64.b64";

        std::vector<unsigned char> inputData(4096);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        const char* allPaths[] = { inputFilePath, hexTextFilePath, base64TextFilePath };
        struct Cleanup
        {
            const char** paths;
            std::size_t count;
            ~Cleanup() { for (std::size_t index = 0; index < count; ++index) { std::remove(paths[index]); } }
        } cleanup = { allPaths, sizeof(allPaths) / sizeof(allPaths[0]) };

        if (!WriteTesterFile(inputFilePath, inputData))
        {
            std::cout << "RunHashFileHexBase64CompositionTest: FAILED to write input file" << std::endl;
            return FILE_IO_ERROR;
        }

        CCryptoApi cryptoApi;

        int requiredDigestSize = 0;
        int status = cryptoApi.ComputeHashFile(inputFilePath, 0, nullptr, &requiredDigestSize, nullptr, nullptr);
        if (status != BUFFER_TOO_SMALL)
        {
            std::cout << "RunHashFileHexBase64CompositionTest: FAILED hash size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> digest(requiredDigestSize);
        int digestSize = 0;
        status = cryptoApi.ComputeHashFile(inputFilePath, requiredDigestSize, &digest[0], &digestSize, nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunHashFileHexBase64CompositionTest: FAILED ComputeHashFile status=" << status << std::endl;
            return status;
        }

        int failures = 0;

        // Hex path: digest -> Hex text file -> back to digest bytes.
        {
            int requiredHexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, true, 0, nullptr, &requiredHexSize);
            std::vector<char> hexText(requiredHexSize);
            int hexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, true, requiredHexSize, &hexText[0], &hexSize);

            std::ofstream hexFileStream(hexTextFilePath, std::ios::binary);
            hexFileStream.write(&hexText[0], static_cast<std::streamsize>(hexText.size()));
            hexFileStream.close();

            std::ifstream hexReadStream(hexTextFilePath, std::ios::binary);
            const std::string hexFromFile((std::istreambuf_iterator<char>(hexReadStream)), std::istreambuf_iterator<char>());

            int requiredDecodedSize = 0;
            CUtils::HexDecode(hexFromFile.c_str(), static_cast<int>(hexFromFile.size()), 0, nullptr, &requiredDecodedSize);
            std::vector<unsigned char> decoded(requiredDecodedSize);
            int decodedSize = 0;
            CUtils::HexDecode(hexFromFile.c_str(), static_cast<int>(hexFromFile.size()), requiredDecodedSize, &decoded[0], &decodedSize);

            if (decodedSize != digestSize || std::memcmp(&decoded[0], &digest[0], digestSize) != 0)
            {
                std::cout << "RunHashFileHexBase64CompositionTest: FAILED Hex path mismatch" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunHashFileHexBase64CompositionTest: PASSED Hex path (" << hexTextFilePath << ")" << std::endl;
            }
        }

        // Base64 path: digest -> Base64 text file -> back to digest bytes.
        {
            int requiredBase64Size = 0;
            CUtils::Base64Encode(&digest[0], digestSize, 0, nullptr, &requiredBase64Size);
            std::vector<char> base64Text(requiredBase64Size);
            int base64Size = 0;
            CUtils::Base64Encode(&digest[0], digestSize, requiredBase64Size, &base64Text[0], &base64Size);

            std::ofstream base64FileStream(base64TextFilePath, std::ios::binary);
            base64FileStream.write(&base64Text[0], static_cast<std::streamsize>(base64Text.size()));
            base64FileStream.close();

            std::ifstream base64ReadStream(base64TextFilePath, std::ios::binary);
            const std::string base64FromFile((std::istreambuf_iterator<char>(base64ReadStream)), std::istreambuf_iterator<char>());

            int requiredDecodedSize = 0;
            CUtils::Base64Decode(base64FromFile.c_str(), static_cast<int>(base64FromFile.size()), 0, nullptr, &requiredDecodedSize);
            std::vector<unsigned char> decoded(requiredDecodedSize);
            int decodedSize = 0;
            CUtils::Base64Decode(base64FromFile.c_str(), static_cast<int>(base64FromFile.size()), requiredDecodedSize, &decoded[0], &decodedSize);

            if (decodedSize != digestSize || std::memcmp(&decoded[0], &digest[0], digestSize) != 0)
            {
                std::cout << "RunHashFileHexBase64CompositionTest: FAILED Base64 path mismatch" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunHashFileHexBase64CompositionTest: PASSED Base64 path (" << base64TextFilePath << ")" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunHashFileHexBase64CompositionTest: PASSED (Hex and Base64 file digest composition round-trips)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunHashFileHexBase64CompositionTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderHashTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC, HASH_SHA256);

        const int hashSize = cryptoApi.GetHashSize();
        if (hashSize != 32)
        {
            std::cout << "RunMicrosoftProviderHashTest: FAILED GetHashSize expected 32 got " << hashSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        struct KnownVector
        {
            const char* text;
            const char* expectedHex;
        };

        const KnownVector knownVectors[] =
        {
            { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
        };

        for (std::size_t index = 0; index < sizeof(knownVectors) / sizeof(knownVectors[0]); ++index)
        {
            const char* text = knownVectors[index].text;
            const char* expectedHex = knownVectors[index].expectedHex;
            const int textSize = static_cast<int>(std::strlen(text));

            int requiredSize = 0;
            int status = cryptoApi.ComputeHashString(text, textSize, 0, nullptr, &requiredSize, nullptr, nullptr);
            if (status != BUFFER_TOO_SMALL || requiredSize != hashSize)
            {
                std::cout << "RunMicrosoftProviderHashTest: FAILED size query status=" << status << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::vector<unsigned char> digest(requiredSize);
            int digestSize = 0;
            status = cryptoApi.ComputeHashString(text, textSize, requiredSize, &digest[0], &digestSize, nullptr, nullptr);
            if (status != NO_ERROR || digestSize != hashSize)
            {
                std::cout << "RunMicrosoftProviderHashTest: FAILED ComputeHashString status=" << status << std::endl;
                return status;
            }

            int requiredHexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, false, 0, nullptr, &requiredHexSize);
            std::vector<char> hexText(requiredHexSize);
            int hexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, false, requiredHexSize, &hexText[0], &hexSize);
            const std::string hexString(hexText.begin(), hexText.end());

            if (hexString != expectedHex)
            {
                std::cout << "RunMicrosoftProviderHashTest: FAILED SHA-256(\"" << text << "\") = " << hexString
                          << " expected " << expectedHex << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::cout << "RunMicrosoftProviderHashTest: PASSED SHA-256(\"" << text << "\") = " << hexString << std::endl;
        }

        const char* consistencyText = "The quick brown fox jumps over the lazy dog";
        const int consistencyTextSize = static_cast<int>(std::strlen(consistencyText));
        const unsigned char* consistencyBytes = reinterpret_cast<const unsigned char*>(consistencyText);

        std::vector<unsigned char> stringDigest(hashSize);
        int stringDigestSize = 0;
        int status = cryptoApi.ComputeHashString(consistencyText, consistencyTextSize, hashSize, &stringDigest[0], &stringDigestSize, nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderHashTest: FAILED consistency ComputeHashString status=" << status << std::endl;
            return status;
        }

        std::vector<unsigned char> bufferDigest(hashSize);
        int bufferDigestSize = 0;
        status = cryptoApi.ComputeHashBuffer(consistencyBytes, consistencyTextSize, hashSize, &bufferDigest[0], &bufferDigestSize, nullptr, nullptr);
        if (status != NO_ERROR || bufferDigestSize != stringDigestSize ||
            std::memcmp(&bufferDigest[0], &stringDigest[0], static_cast<std::size_t>(stringDigestSize)) != 0)
        {
            std::cout << "RunMicrosoftProviderHashTest: FAILED ComputeHashBuffer mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* tempFilePath = "cryptoapi_msft_hash_test.bin";
        std::vector<unsigned char> fileContent(consistencyBytes, consistencyBytes + consistencyTextSize);
        if (!WriteTesterFile(tempFilePath, fileContent))
        {
            std::cout << "RunMicrosoftProviderHashTest: FAILED to write temp file" << std::endl;
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> fileDigest(hashSize);
        int fileDigestSize = 0;
        status = cryptoApi.ComputeHashFile(tempFilePath, hashSize, &fileDigest[0], &fileDigestSize, nullptr, nullptr);
        std::remove(tempFilePath);

        if (status != NO_ERROR || fileDigestSize != stringDigestSize ||
            std::memcmp(&fileDigest[0], &stringDigest[0], static_cast<std::size_t>(stringDigestSize)) != 0)
        {
            std::cout << "RunMicrosoftProviderHashTest: FAILED ComputeHashFile mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderHashTest: PASSED Buffer/String/File consistency" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderHashTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC, HASH_SHA256);

        const int hashSize = cryptoApi.GetHashSize();
        if (hashSize != 32)
        {
            std::cout << "RunCryptoPPProviderHashTest: FAILED GetHashSize expected 32 got " << hashSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        struct KnownVector
        {
            const char* text;
            const char* expectedHex;
        };

        const KnownVector knownVectors[] =
        {
            { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
        };

        for (std::size_t index = 0; index < sizeof(knownVectors) / sizeof(knownVectors[0]); ++index)
        {
            const char* text = knownVectors[index].text;
            const char* expectedHex = knownVectors[index].expectedHex;
            const int textSize = static_cast<int>(std::strlen(text));

            int requiredSize = 0;
            int status = cryptoApi.ComputeHashString(text, textSize, 0, nullptr, &requiredSize, nullptr, nullptr);
            if (status != BUFFER_TOO_SMALL || requiredSize != hashSize)
            {
                std::cout << "RunCryptoPPProviderHashTest: FAILED size query status=" << status << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::vector<unsigned char> digest(requiredSize);
            int digestSize = 0;
            status = cryptoApi.ComputeHashString(text, textSize, requiredSize, &digest[0], &digestSize, nullptr, nullptr);
            if (status != NO_ERROR || digestSize != hashSize)
            {
                std::cout << "RunCryptoPPProviderHashTest: FAILED ComputeHashString status=" << status << std::endl;
                return status;
            }

            int requiredHexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, false, 0, nullptr, &requiredHexSize);
            std::vector<char> hexText(requiredHexSize);
            int hexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, false, requiredHexSize, &hexText[0], &hexSize);
            const std::string hexString(hexText.begin(), hexText.end());

            if (hexString != expectedHex)
            {
                std::cout << "RunCryptoPPProviderHashTest: FAILED SHA-256(\"" << text << "\") = " << hexString
                          << " expected " << expectedHex << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::cout << "RunCryptoPPProviderHashTest: PASSED SHA-256(\"" << text << "\") = " << hexString << std::endl;
        }

        const char* consistencyText = "The quick brown fox jumps over the lazy dog";
        const int consistencyTextSize = static_cast<int>(std::strlen(consistencyText));
        const unsigned char* consistencyBytes = reinterpret_cast<const unsigned char*>(consistencyText);

        std::vector<unsigned char> stringDigest(hashSize);
        int stringDigestSize = 0;
        int status = cryptoApi.ComputeHashString(consistencyText, consistencyTextSize, hashSize, &stringDigest[0], &stringDigestSize, nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderHashTest: FAILED consistency ComputeHashString status=" << status << std::endl;
            return status;
        }

        std::vector<unsigned char> bufferDigest(hashSize);
        int bufferDigestSize = 0;
        status = cryptoApi.ComputeHashBuffer(consistencyBytes, consistencyTextSize, hashSize, &bufferDigest[0], &bufferDigestSize, nullptr, nullptr);
        if (status != NO_ERROR || bufferDigestSize != stringDigestSize ||
            std::memcmp(&bufferDigest[0], &stringDigest[0], static_cast<std::size_t>(stringDigestSize)) != 0)
        {
            std::cout << "RunCryptoPPProviderHashTest: FAILED ComputeHashBuffer mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* tempFilePath = "cryptoapi_cryptopp_hash_test.bin";
        std::vector<unsigned char> fileContent(consistencyBytes, consistencyBytes + consistencyTextSize);
        if (!WriteTesterFile(tempFilePath, fileContent))
        {
            std::cout << "RunCryptoPPProviderHashTest: FAILED to write temp file" << std::endl;
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> fileDigest(hashSize);
        int fileDigestSize = 0;
        status = cryptoApi.ComputeHashFile(tempFilePath, hashSize, &fileDigest[0], &fileDigestSize, nullptr, nullptr);
        std::remove(tempFilePath);

        if (status != NO_ERROR || fileDigestSize != stringDigestSize ||
            std::memcmp(&fileDigest[0], &stringDigest[0], static_cast<std::size_t>(stringDigestSize)) != 0)
        {
            std::cout << "RunCryptoPPProviderHashTest: FAILED ComputeHashFile mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderHashTest: PASSED Buffer/String/File consistency" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderHashTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC, HASH_SHA256);

        const int hashSize = cryptoApi.GetHashSize();
        if (hashSize != 32)
        {
            std::cout << "RunBotanProviderHashTest: FAILED GetHashSize expected 32 got " << hashSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        struct KnownVector
        {
            const char* text;
            const char* expectedHex;
        };

        const KnownVector knownVectors[] =
        {
            { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
        };

        for (std::size_t index = 0; index < sizeof(knownVectors) / sizeof(knownVectors[0]); ++index)
        {
            const char* text = knownVectors[index].text;
            const char* expectedHex = knownVectors[index].expectedHex;
            const int textSize = static_cast<int>(std::strlen(text));

            int requiredSize = 0;
            int status = cryptoApi.ComputeHashString(text, textSize, 0, nullptr, &requiredSize, nullptr, nullptr);
            if (status != BUFFER_TOO_SMALL || requiredSize != hashSize)
            {
                std::cout << "RunBotanProviderHashTest: FAILED size query status=" << status << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::vector<unsigned char> digest(requiredSize);
            int digestSize = 0;
            status = cryptoApi.ComputeHashString(text, textSize, requiredSize, &digest[0], &digestSize, nullptr, nullptr);
            if (status != NO_ERROR || digestSize != hashSize)
            {
                std::cout << "RunBotanProviderHashTest: FAILED ComputeHashString status=" << status << std::endl;
                return status;
            }

            int requiredHexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, false, 0, nullptr, &requiredHexSize);
            std::vector<char> hexText(requiredHexSize);
            int hexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, false, requiredHexSize, &hexText[0], &hexSize);
            const std::string hexString(hexText.begin(), hexText.end());

            if (hexString != expectedHex)
            {
                std::cout << "RunBotanProviderHashTest: FAILED SHA-256(\"" << text << "\") = " << hexString
                          << " expected " << expectedHex << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::cout << "RunBotanProviderHashTest: PASSED SHA-256(\"" << text << "\") = " << hexString << std::endl;
        }

        const char* consistencyText = "The quick brown fox jumps over the lazy dog";
        const int consistencyTextSize = static_cast<int>(std::strlen(consistencyText));
        const unsigned char* consistencyBytes = reinterpret_cast<const unsigned char*>(consistencyText);

        std::vector<unsigned char> stringDigest(hashSize);
        int stringDigestSize = 0;
        int status = cryptoApi.ComputeHashString(consistencyText, consistencyTextSize, hashSize, &stringDigest[0], &stringDigestSize, nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderHashTest: FAILED consistency ComputeHashString status=" << status << std::endl;
            return status;
        }

        std::vector<unsigned char> bufferDigest(hashSize);
        int bufferDigestSize = 0;
        status = cryptoApi.ComputeHashBuffer(consistencyBytes, consistencyTextSize, hashSize, &bufferDigest[0], &bufferDigestSize, nullptr, nullptr);
        if (status != NO_ERROR || bufferDigestSize != stringDigestSize ||
            std::memcmp(&bufferDigest[0], &stringDigest[0], static_cast<std::size_t>(stringDigestSize)) != 0)
        {
            std::cout << "RunBotanProviderHashTest: FAILED ComputeHashBuffer mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* tempFilePath = "cryptoapi_botan_hash_test.bin";
        std::vector<unsigned char> fileContent(consistencyBytes, consistencyBytes + consistencyTextSize);
        if (!WriteTesterFile(tempFilePath, fileContent))
        {
            std::cout << "RunBotanProviderHashTest: FAILED to write temp file" << std::endl;
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> fileDigest(hashSize);
        int fileDigestSize = 0;
        status = cryptoApi.ComputeHashFile(tempFilePath, hashSize, &fileDigest[0], &fileDigestSize, nullptr, nullptr);
        std::remove(tempFilePath);

        if (status != NO_ERROR || fileDigestSize != stringDigestSize ||
            std::memcmp(&fileDigest[0], &stringDigest[0], static_cast<std::size_t>(stringDigestSize)) != 0)
        {
            std::cout << "RunBotanProviderHashTest: FAILED ComputeHashFile mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderHashTest: PASSED Buffer/String/File consistency" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderHashTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC, HASH_SHA256);

        const int hashSize = cryptoApi.GetHashSize();
        if (hashSize != 32)
        {
            std::cout << "RunOpenSslProviderHashTest: FAILED GetHashSize expected 32 got " << hashSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        struct KnownVector
        {
            const char* text;
            const char* expectedHex;
        };

        const KnownVector knownVectors[] =
        {
            { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
        };

        for (std::size_t index = 0; index < sizeof(knownVectors) / sizeof(knownVectors[0]); ++index)
        {
            const char* text = knownVectors[index].text;
            const char* expectedHex = knownVectors[index].expectedHex;
            const int textSize = static_cast<int>(std::strlen(text));

            int requiredSize = 0;
            int status = cryptoApi.ComputeHashString(text, textSize, 0, nullptr, &requiredSize, nullptr, nullptr);
            if (status != BUFFER_TOO_SMALL || requiredSize != hashSize)
            {
                std::cout << "RunOpenSslProviderHashTest: FAILED size query status=" << status << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::vector<unsigned char> digest(requiredSize);
            int digestSize = 0;
            status = cryptoApi.ComputeHashString(text, textSize, requiredSize, &digest[0], &digestSize, nullptr, nullptr);
            if (status != NO_ERROR || digestSize != hashSize)
            {
                std::cout << "RunOpenSslProviderHashTest: FAILED ComputeHashString status=" << status << std::endl;
                return status;
            }

            int requiredHexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, false, 0, nullptr, &requiredHexSize);
            std::vector<char> hexText(requiredHexSize);
            int hexSize = 0;
            CUtils::HexEncode(&digest[0], digestSize, false, requiredHexSize, &hexText[0], &hexSize);
            const std::string hexString(hexText.begin(), hexText.end());

            if (hexString != expectedHex)
            {
                std::cout << "RunOpenSslProviderHashTest: FAILED SHA-256(\"" << text << "\") = " << hexString
                          << " expected " << expectedHex << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::cout << "RunOpenSslProviderHashTest: PASSED SHA-256(\"" << text << "\") = " << hexString << std::endl;
        }

        const char* consistencyText = "The quick brown fox jumps over the lazy dog";
        const int consistencyTextSize = static_cast<int>(std::strlen(consistencyText));
        const unsigned char* consistencyBytes = reinterpret_cast<const unsigned char*>(consistencyText);

        std::vector<unsigned char> stringDigest(hashSize);
        int stringDigestSize = 0;
        int status = cryptoApi.ComputeHashString(consistencyText, consistencyTextSize, hashSize, &stringDigest[0], &stringDigestSize, nullptr, nullptr);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderHashTest: FAILED consistency ComputeHashString status=" << status << std::endl;
            return status;
        }

        std::vector<unsigned char> bufferDigest(hashSize);
        int bufferDigestSize = 0;
        status = cryptoApi.ComputeHashBuffer(consistencyBytes, consistencyTextSize, hashSize, &bufferDigest[0], &bufferDigestSize, nullptr, nullptr);
        if (status != NO_ERROR || bufferDigestSize != stringDigestSize ||
            std::memcmp(&bufferDigest[0], &stringDigest[0], static_cast<std::size_t>(stringDigestSize)) != 0)
        {
            std::cout << "RunOpenSslProviderHashTest: FAILED ComputeHashBuffer mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* tempFilePath = "cryptoapi_openssl_hash_test.bin";
        std::vector<unsigned char> fileContent(consistencyBytes, consistencyBytes + consistencyTextSize);
        if (!WriteTesterFile(tempFilePath, fileContent))
        {
            std::cout << "RunOpenSslProviderHashTest: FAILED to write temp file" << std::endl;
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> fileDigest(hashSize);
        int fileDigestSize = 0;
        status = cryptoApi.ComputeHashFile(tempFilePath, hashSize, &fileDigest[0], &fileDigestSize, nullptr, nullptr);
        std::remove(tempFilePath);

        if (status != NO_ERROR || fileDigestSize != stringDigestSize ||
            std::memcmp(&fileDigest[0], &stringDigest[0], static_cast<std::size_t>(stringDigestSize)) != 0)
        {
            std::cout << "RunOpenSslProviderHashTest: FAILED ComputeHashFile mismatch status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderHashTest: PASSED Buffer/String/File consistency" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashAlgorithmsTest(void)
{
    try
    {
        struct ProviderCase
        {
            ProviderKind kind;
            const char* name;
        };

        const ProviderCase providerCases[] =
        {
            { PROVIDER_MICROSOFT, "Microsoft" },
            { PROVIDER_CRYPTOPP,  "CryptoPP" },
            { PROVIDER_BOTAN,     "Botan" },
            { PROVIDER_OPENSSL,   "OpenSSL" }
        };

        struct HashCase
        {
            HashAlgorithm algorithm;
            const char* name;
        };

        const HashCase hashCases[] =
        {
            { HASH_MD5,        "MD5" },
            { HASH_SHA1,       "SHA1" },
            { HASH_SHA224,     "SHA224" },
            { HASH_SHA256,     "SHA256" },
            { HASH_SHA384,     "SHA384" },
            { HASH_SHA512,     "SHA512" },
            { HASH_SHA512_256, "SHA512_256" },
            { HASH_SHA3_224,   "SHA3_224" },
            { HASH_SHA3_256,   "SHA3_256" },
            { HASH_SHA3_384,   "SHA3_384" },
            { HASH_SHA3_512,   "SHA3_512" },
            { HASH_BLAKE2B,    "BLAKE2B" },
            { HASH_BLAKE2S,    "BLAKE2S" },
            { HASH_RIPEMD160,  "RIPEMD160" }
        };

        const unsigned char testData[] = { 'C', 'r', 'y', 'p', 't', 'o', 'A', 'P', 'I', ' ', 'h', 'a', 's', 'h' };
        const int testDataSize = static_cast<int>(sizeof(testData));

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t providerIndex = 0; providerIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++providerIndex)
        {
            const ProviderKind kind = providerCases[providerIndex].kind;
            const char* providerName = providerCases[providerIndex].name;

            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
            if (!factory)
            {
                std::cout << "RunHashAlgorithmsTest: FAILED [" << providerName << "] CreateProviderFactory" << std::endl;
                ++failures;
                continue;
            }

            for (std::size_t hashIndex = 0; hashIndex < sizeof(hashCases) / sizeof(hashCases[0]); ++hashIndex)
            {
                const HashAlgorithm algorithm = hashCases[hashIndex].algorithm;
                const char* algorithmName = hashCases[hashIndex].name;
                const bool supported = factory->SupportsHashAlgorithm(algorithm);

                CCryptoApi cryptoApi(kind, AEAD_AES_256_GCM, ASYMMETRIC_RSA_2048, LEGACY_AES_256_CBC, algorithm);
                const int hashSize = cryptoApi.GetHashSize();

                if (!supported)
                {
                    if (hashSize != 0)
                    {
                        std::cout << "RunHashAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                                  << "] expected unsupported but GetHashSize=" << hashSize << std::endl;
                        ++failures;
                    }
                    else
                    {
                        std::cout << "RunHashAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                                  << "] correctly unsupported" << std::endl;
                    }
                    continue;
                }

                ++supportedCount;

                if (hashSize <= 0)
                {
                    std::cout << "RunHashAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] GetHashSize=" << hashSize << " for a supported algorithm" << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> digest(static_cast<std::size_t>(hashSize));
                int digestSize = 0;
                const int status = cryptoApi.ComputeHashBuffer(testData, testDataSize, hashSize, &digest[0], &digestSize, nullptr, nullptr);
                if (status != NO_ERROR || digestSize != hashSize)
                {
                    std::cout << "RunHashAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] ComputeHashBuffer status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::cout << "RunHashAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                          << "] digest (" << digestSize << " bytes)" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunHashAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and computed)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunHashAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderSignatureTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_MICROSOFT, SIGNATURE_ECDSA_P256_SHA256);

        int status = cryptoApi.GenerateSignatureKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderSignatureTest: FAILED GenerateSignatureKeyPair status=" << status << std::endl;
            return status;
        }

        const int signatureSize = cryptoApi.GetSignatureSize();
        if (signatureSize != 64)
        {
            std::cout << "RunMicrosoftProviderSignatureTest: FAILED GetSignatureSize expected 64 got " << signatureSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* message = "RunMicrosoftProviderSignatureTest message to sign";
        const int messageSize = static_cast<int>(std::strlen(message));
        const unsigned char* messageBytes = reinterpret_cast<const unsigned char*>(message);

        int requiredSize = 0;
        status = cryptoApi.SignBuffer(messageBytes, messageSize, 0, nullptr, &requiredSize);
        if (status != BUFFER_TOO_SMALL || requiredSize != signatureSize)
        {
            std::cout << "RunMicrosoftProviderSignatureTest: FAILED sign size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> signature(requiredSize);
        int actualSignatureSize = 0;
        status = cryptoApi.SignBuffer(messageBytes, messageSize, requiredSize, &signature[0], &actualSignatureSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderSignatureTest: FAILED SignBuffer status=" << status << std::endl;
            return status;
        }

        bool isValid = false;
        status = cryptoApi.VerifyBuffer(messageBytes, messageSize, &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || !isValid)
        {
            std::cout << "RunMicrosoftProviderSignatureTest: FAILED round-trip verify status=" << status << " valid=" << isValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderSignatureTest: PASSED sign+verify round-trip (" << actualSignatureSize << " bytes)" << std::endl;

        std::string tamperedMessage(message);
        tamperedMessage[0] = static_cast<char>(tamperedMessage[0] ^ 0xFF);
        isValid = true;
        status = cryptoApi.VerifyBuffer(reinterpret_cast<const unsigned char*>(tamperedMessage.data()), messageSize,
                                        &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || isValid)
        {
            std::cout << "RunMicrosoftProviderSignatureTest: FAILED tampered-message not rejected status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> tamperedSignature(signature);
        tamperedSignature[tamperedSignature.size() - 1] ^= 0xFF;
        isValid = true;
        status = cryptoApi.VerifyBuffer(messageBytes, messageSize, &tamperedSignature[0],
                                        static_cast<int>(tamperedSignature.size()), &isValid);
        if (status != NO_ERROR || isValid)
        {
            std::cout << "RunMicrosoftProviderSignatureTest: FAILED tampered-signature not rejected status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderSignatureTest: PASSED tampered message / tampered signature both rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderSignatureTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, SIGNATURE_RSA_PSS_SHA256_2048);

        int status = cryptoApi.GenerateSignatureKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderSignatureTest: FAILED GenerateSignatureKeyPair status=" << status << std::endl;
            return status;
        }

        const int signatureSize = cryptoApi.GetSignatureSize();
        if (signatureSize != 256)
        {
            std::cout << "RunCryptoPPProviderSignatureTest: FAILED GetSignatureSize expected 256 got " << signatureSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* message = "RunCryptoPPProviderSignatureTest message to sign";
        const int messageSize = static_cast<int>(std::strlen(message));
        const unsigned char* messageBytes = reinterpret_cast<const unsigned char*>(message);

        int requiredSize = 0;
        status = cryptoApi.SignBuffer(messageBytes, messageSize, 0, nullptr, &requiredSize);
        if (status != BUFFER_TOO_SMALL || requiredSize != signatureSize)
        {
            std::cout << "RunCryptoPPProviderSignatureTest: FAILED sign size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> signature(requiredSize);
        int actualSignatureSize = 0;
        status = cryptoApi.SignBuffer(messageBytes, messageSize, requiredSize, &signature[0], &actualSignatureSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderSignatureTest: FAILED SignBuffer status=" << status << std::endl;
            return status;
        }

        bool isValid = false;
        status = cryptoApi.VerifyBuffer(messageBytes, messageSize, &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || !isValid)
        {
            std::cout << "RunCryptoPPProviderSignatureTest: FAILED round-trip verify status=" << status << " valid=" << isValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderSignatureTest: PASSED sign+verify round-trip (" << actualSignatureSize << " bytes)" << std::endl;

        std::string tamperedMessage(message);
        tamperedMessage[0] = static_cast<char>(tamperedMessage[0] ^ 0xFF);
        isValid = true;
        status = cryptoApi.VerifyBuffer(reinterpret_cast<const unsigned char*>(tamperedMessage.data()), messageSize,
                                        &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || isValid)
        {
            std::cout << "RunCryptoPPProviderSignatureTest: FAILED tampered-message not rejected status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> tamperedSignature(signature);
        tamperedSignature[tamperedSignature.size() - 1] ^= 0xFF;
        isValid = true;
        status = cryptoApi.VerifyBuffer(messageBytes, messageSize, &tamperedSignature[0],
                                        static_cast<int>(tamperedSignature.size()), &isValid);
        if (status != NO_ERROR || isValid)
        {
            std::cout << "RunCryptoPPProviderSignatureTest: FAILED tampered-signature not rejected status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderSignatureTest: PASSED tampered message / tampered signature both rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderSignatureTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_BOTAN, SIGNATURE_ED25519);

        int status = cryptoApi.GenerateSignatureKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderSignatureTest: FAILED GenerateSignatureKeyPair status=" << status << std::endl;
            return status;
        }

        const int signatureSize = cryptoApi.GetSignatureSize();
        if (signatureSize != 64)
        {
            std::cout << "RunBotanProviderSignatureTest: FAILED GetSignatureSize expected 64 got " << signatureSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* message = "RunBotanProviderSignatureTest message to sign";
        const int messageSize = static_cast<int>(std::strlen(message));
        const unsigned char* messageBytes = reinterpret_cast<const unsigned char*>(message);

        int requiredSize = 0;
        status = cryptoApi.SignBuffer(messageBytes, messageSize, 0, nullptr, &requiredSize);
        if (status != BUFFER_TOO_SMALL || requiredSize != signatureSize)
        {
            std::cout << "RunBotanProviderSignatureTest: FAILED sign size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> signature(requiredSize);
        int actualSignatureSize = 0;
        status = cryptoApi.SignBuffer(messageBytes, messageSize, requiredSize, &signature[0], &actualSignatureSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderSignatureTest: FAILED SignBuffer status=" << status << std::endl;
            return status;
        }

        bool isValid = false;
        status = cryptoApi.VerifyBuffer(messageBytes, messageSize, &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || !isValid)
        {
            std::cout << "RunBotanProviderSignatureTest: FAILED round-trip verify status=" << status << " valid=" << isValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderSignatureTest: PASSED sign+verify round-trip (" << actualSignatureSize << " bytes)" << std::endl;

        std::string tamperedMessage(message);
        tamperedMessage[0] = static_cast<char>(tamperedMessage[0] ^ 0xFF);
        isValid = true;
        status = cryptoApi.VerifyBuffer(reinterpret_cast<const unsigned char*>(tamperedMessage.data()), messageSize,
                                        &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || isValid)
        {
            std::cout << "RunBotanProviderSignatureTest: FAILED tampered-message not rejected status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> tamperedSignature(signature);
        tamperedSignature[tamperedSignature.size() - 1] ^= 0xFF;
        isValid = true;
        status = cryptoApi.VerifyBuffer(messageBytes, messageSize, &tamperedSignature[0],
                                        static_cast<int>(tamperedSignature.size()), &isValid);
        if (status != NO_ERROR || isValid)
        {
            std::cout << "RunBotanProviderSignatureTest: FAILED tampered-signature not rejected status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderSignatureTest: PASSED tampered message / tampered signature both rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderSignatureTest(void)
{
    try
    {
        CCryptoApi cryptoApi(PROVIDER_OPENSSL, SIGNATURE_ECDSA_P256_SHA256);

        int status = cryptoApi.GenerateSignatureKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderSignatureTest: FAILED GenerateSignatureKeyPair status=" << status << std::endl;
            return status;
        }

        const int signatureSize = cryptoApi.GetSignatureSize();
        if (signatureSize != 64)
        {
            std::cout << "RunOpenSslProviderSignatureTest: FAILED GetSignatureSize expected 64 got " << signatureSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* message = "RunOpenSslProviderSignatureTest message to sign";
        const int messageSize = static_cast<int>(std::strlen(message));
        const unsigned char* messageBytes = reinterpret_cast<const unsigned char*>(message);

        int requiredSize = 0;
        status = cryptoApi.SignBuffer(messageBytes, messageSize, 0, nullptr, &requiredSize);
        if (status != BUFFER_TOO_SMALL || requiredSize != signatureSize)
        {
            std::cout << "RunOpenSslProviderSignatureTest: FAILED sign size query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> signature(requiredSize);
        int actualSignatureSize = 0;
        status = cryptoApi.SignBuffer(messageBytes, messageSize, requiredSize, &signature[0], &actualSignatureSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderSignatureTest: FAILED SignBuffer status=" << status << std::endl;
            return status;
        }

        bool isValid = false;
        status = cryptoApi.VerifyBuffer(messageBytes, messageSize, &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || !isValid)
        {
            std::cout << "RunOpenSslProviderSignatureTest: FAILED round-trip verify status=" << status << " valid=" << isValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderSignatureTest: PASSED sign+verify round-trip (" << actualSignatureSize << " bytes)" << std::endl;

        std::string tamperedMessage(message);
        tamperedMessage[0] = static_cast<char>(tamperedMessage[0] ^ 0xFF);
        isValid = true;
        status = cryptoApi.VerifyBuffer(reinterpret_cast<const unsigned char*>(tamperedMessage.data()), messageSize,
                                        &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || isValid)
        {
            std::cout << "RunOpenSslProviderSignatureTest: FAILED tampered-message not rejected status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> tamperedSignature(signature);
        tamperedSignature[tamperedSignature.size() - 1] ^= 0xFF;
        isValid = true;
        status = cryptoApi.VerifyBuffer(messageBytes, messageSize, &tamperedSignature[0],
                                        static_cast<int>(tamperedSignature.size()), &isValid);
        if (status != NO_ERROR || isValid)
        {
            std::cout << "RunOpenSslProviderSignatureTest: FAILED tampered-signature not rejected status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderSignatureTest: PASSED tampered message / tampered signature both rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunSignatureAlgorithmsTest(void)
{
    try
    {
        struct ProviderCase
        {
            ProviderKind kind;
            const char* name;
        };

        const ProviderCase providerCases[] =
        {
            { PROVIDER_MICROSOFT, "Microsoft" },
            { PROVIDER_CRYPTOPP,  "CryptoPP" },
            { PROVIDER_BOTAN,     "Botan" },
            { PROVIDER_OPENSSL,   "OpenSSL" }
        };

        struct SignatureCase
        {
            SignatureAlgorithm algorithm;
            const char* name;
        };

        const SignatureCase signatureCases[] =
        {
            { SIGNATURE_RSA_PSS_SHA256_2048, "RSA_PSS_SHA256_2048" },
            { SIGNATURE_RSA_PSS_SHA256_3072, "RSA_PSS_SHA256_3072" },
            { SIGNATURE_RSA_PSS_SHA256_4096, "RSA_PSS_SHA256_4096" },
            { SIGNATURE_ECDSA_P256_SHA256,   "ECDSA_P256_SHA256" },
            { SIGNATURE_ED25519,             "Ed25519" },
            { SIGNATURE_ECDSA_P384_SHA384,   "ECDSA_P384_SHA384" },
            { SIGNATURE_ECDSA_P521_SHA512,   "ECDSA_P521_SHA512" },
            { SIGNATURE_DSA_SHA256_2048,     "DSA_SHA256_2048" },
            { SIGNATURE_DSA_SHA256_3072,     "DSA_SHA256_3072" }
        };

        const unsigned char testData[] = { 'C', 'r', 'y', 'p', 't', 'o', 'A', 'P', 'I', ' ', 's', 'i', 'g', 'n' };
        const int testDataSize = static_cast<int>(sizeof(testData));

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t providerIndex = 0; providerIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++providerIndex)
        {
            const ProviderKind kind = providerCases[providerIndex].kind;
            const char* providerName = providerCases[providerIndex].name;

            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
            if (!factory)
            {
                std::cout << "RunSignatureAlgorithmsTest: FAILED [" << providerName << "] CreateProviderFactory" << std::endl;
                ++failures;
                continue;
            }

            for (std::size_t sigIndex = 0; sigIndex < sizeof(signatureCases) / sizeof(signatureCases[0]); ++sigIndex)
            {
                const SignatureAlgorithm algorithm = signatureCases[sigIndex].algorithm;
                const char* algorithmName = signatureCases[sigIndex].name;
                const bool supported = factory->SupportsSignatureAlgorithm(algorithm);

                CCryptoApi cryptoApi(kind, algorithm);
                const int keyPairStatus = cryptoApi.GenerateSignatureKeyPair();

                if (!supported)
                {
                    if (keyPairStatus == NO_ERROR)
                    {
                        std::cout << "RunSignatureAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                                  << "] expected unsupported but GenerateSignatureKeyPair succeeded" << std::endl;
                        ++failures;
                    }
                    else
                    {
                        std::cout << "RunSignatureAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                                  << "] correctly unsupported" << std::endl;
                    }
                    continue;
                }

                ++supportedCount;

                if (keyPairStatus != NO_ERROR)
                {
                    std::cout << "RunSignatureAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] GenerateSignatureKeyPair status=" << keyPairStatus << " for a supported algorithm" << std::endl;
                    ++failures;
                    continue;
                }

                const int signatureSize = cryptoApi.GetSignatureSize();
                if (signatureSize <= 0)
                {
                    std::cout << "RunSignatureAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] GetSignatureSize=" << signatureSize << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> signature(static_cast<std::size_t>(signatureSize));
                int actualSignatureSize = 0;
                int status = cryptoApi.SignBuffer(testData, testDataSize, signatureSize, &signature[0], &actualSignatureSize);
                if (status != NO_ERROR || actualSignatureSize != signatureSize)
                {
                    std::cout << "RunSignatureAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] SignBuffer status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                bool isValid = false;
                status = cryptoApi.VerifyBuffer(testData, testDataSize, &signature[0], actualSignatureSize, &isValid);
                if (status != NO_ERROR || !isValid)
                {
                    std::cout << "RunSignatureAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] VerifyBuffer status=" << status << " valid=" << isValid << std::endl;
                    ++failures;
                    continue;
                }

                std::cout << "RunSignatureAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                          << "] signature (" << actualSignatureSize << " bytes)" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunSignatureAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and computed)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunSignatureAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderKeyAgreementTest(void)
{
    try
    {
        CCryptoApi alice(PROVIDER_MICROSOFT, KEYAGREEMENT_ECDH_P256);
        CCryptoApi bob(PROVIDER_MICROSOFT, KEYAGREEMENT_ECDH_P256);

        int status = alice.GenerateKeyAgreementKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED alice GenerateKeyAgreementKeyPair status=" << status << std::endl;
            return status;
        }

        status = bob.GenerateKeyAgreementKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED bob GenerateKeyAgreementKeyPair status=" << status << std::endl;
            return status;
        }

        const int publicKeySize = alice.GetKeyAgreementPublicKeySize();
        if (publicKeySize != 72 || bob.GetKeyAgreementPublicKeySize() != publicKeySize)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED GetKeyAgreementPublicKeySize expected 72 alice=" << publicKeySize
                      << " bob=" << bob.GetKeyAgreementPublicKeySize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        const int sharedSecretSize = alice.GetSharedSecretSize();
        if (sharedSecretSize != 32 || bob.GetSharedSecretSize() != sharedSecretSize)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED GetSharedSecretSize expected 32 alice=" << sharedSecretSize
                      << " bob=" << bob.GetSharedSecretSize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> alicePublicKey(static_cast<std::size_t>(publicKeySize));
        int aliceActualPublicKeySize = 0;
        status = alice.ExportKeyAgreementPublicKey(publicKeySize, &alicePublicKey[0], &aliceActualPublicKeySize);
        if (status != NO_ERROR || aliceActualPublicKeySize != publicKeySize)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED alice ExportKeyAgreementPublicKey status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bobPublicKey(static_cast<std::size_t>(publicKeySize));
        int bobActualPublicKeySize = 0;
        status = bob.ExportKeyAgreementPublicKey(publicKeySize, &bobPublicKey[0], &bobActualPublicKeySize);
        if (status != NO_ERROR || bobActualPublicKeySize != publicKeySize)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED bob ExportKeyAgreementPublicKey status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> aliceSharedSecret(static_cast<std::size_t>(sharedSecretSize));
        int aliceSharedSecretSize = 0;
        status = alice.DeriveSharedSecret(&bobPublicKey[0], bobActualPublicKeySize, sharedSecretSize, &aliceSharedSecret[0], &aliceSharedSecretSize);
        if (status != NO_ERROR || aliceSharedSecretSize != sharedSecretSize)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED alice DeriveSharedSecret status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bobSharedSecret(static_cast<std::size_t>(sharedSecretSize));
        int bobSharedSecretSize = 0;
        status = bob.DeriveSharedSecret(&alicePublicKey[0], aliceActualPublicKeySize, sharedSecretSize, &bobSharedSecret[0], &bobSharedSecretSize);
        if (status != NO_ERROR || bobSharedSecretSize != sharedSecretSize)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED bob DeriveSharedSecret status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        if (aliceSharedSecret != bobSharedSecret)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED alice/bob shared secrets do not match" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderKeyAgreementTest: PASSED alice/bob agree on shared secret (" << sharedSecretSize << " bytes)" << std::endl;

        std::vector<unsigned char> tamperedBobPublicKey(bobPublicKey);
        tamperedBobPublicKey[0] = static_cast<unsigned char>(tamperedBobPublicKey[0] ^ 0xFF);
        std::vector<unsigned char> aliceSharedSecretWithTamperedPeer(static_cast<std::size_t>(sharedSecretSize));
        int aliceTamperedSize = 0;
        const int tamperedStatus = alice.DeriveSharedSecret(&tamperedBobPublicKey[0], static_cast<int>(tamperedBobPublicKey.size()),
                                                             sharedSecretSize, &aliceSharedSecretWithTamperedPeer[0], &aliceTamperedSize);
        if (tamperedStatus == NO_ERROR && aliceSharedSecretWithTamperedPeer == aliceSharedSecret)
        {
            std::cout << "RunMicrosoftProviderKeyAgreementTest: FAILED tampered peer public key produced identical shared secret" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderKeyAgreementTest: PASSED tampered peer public key rejected or yields a different secret" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderKeyAgreementTest(void)
{
    try
    {
        CCryptoApi alice(PROVIDER_CRYPTOPP, KEYAGREEMENT_ECDH_P256);
        CCryptoApi bob(PROVIDER_CRYPTOPP, KEYAGREEMENT_ECDH_P256);

        int status = alice.GenerateKeyAgreementKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED alice GenerateKeyAgreementKeyPair status=" << status << std::endl;
            return status;
        }

        status = bob.GenerateKeyAgreementKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED bob GenerateKeyAgreementKeyPair status=" << status << std::endl;
            return status;
        }

        const int publicKeySize = alice.GetKeyAgreementPublicKeySize();
        if (publicKeySize != 65 || bob.GetKeyAgreementPublicKeySize() != publicKeySize)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED GetKeyAgreementPublicKeySize expected 65 alice=" << publicKeySize
                      << " bob=" << bob.GetKeyAgreementPublicKeySize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        const int sharedSecretSize = alice.GetSharedSecretSize();
        if (sharedSecretSize != 32 || bob.GetSharedSecretSize() != sharedSecretSize)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED GetSharedSecretSize expected 32 alice=" << sharedSecretSize
                      << " bob=" << bob.GetSharedSecretSize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> alicePublicKey(static_cast<std::size_t>(publicKeySize));
        int aliceActualPublicKeySize = 0;
        status = alice.ExportKeyAgreementPublicKey(publicKeySize, &alicePublicKey[0], &aliceActualPublicKeySize);
        if (status != NO_ERROR || aliceActualPublicKeySize != publicKeySize)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED alice ExportKeyAgreementPublicKey status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bobPublicKey(static_cast<std::size_t>(publicKeySize));
        int bobActualPublicKeySize = 0;
        status = bob.ExportKeyAgreementPublicKey(publicKeySize, &bobPublicKey[0], &bobActualPublicKeySize);
        if (status != NO_ERROR || bobActualPublicKeySize != publicKeySize)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED bob ExportKeyAgreementPublicKey status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> aliceSharedSecret(static_cast<std::size_t>(sharedSecretSize));
        int aliceSharedSecretSize = 0;
        status = alice.DeriveSharedSecret(&bobPublicKey[0], bobActualPublicKeySize, sharedSecretSize, &aliceSharedSecret[0], &aliceSharedSecretSize);
        if (status != NO_ERROR || aliceSharedSecretSize != sharedSecretSize)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED alice DeriveSharedSecret status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bobSharedSecret(static_cast<std::size_t>(sharedSecretSize));
        int bobSharedSecretSize = 0;
        status = bob.DeriveSharedSecret(&alicePublicKey[0], aliceActualPublicKeySize, sharedSecretSize, &bobSharedSecret[0], &bobSharedSecretSize);
        if (status != NO_ERROR || bobSharedSecretSize != sharedSecretSize)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED bob DeriveSharedSecret status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        if (aliceSharedSecret != bobSharedSecret)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED alice/bob shared secrets do not match" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderKeyAgreementTest: PASSED alice/bob agree on shared secret (" << sharedSecretSize << " bytes)" << std::endl;

        std::vector<unsigned char> tamperedBobPublicKey(bobPublicKey);
        tamperedBobPublicKey[0] = static_cast<unsigned char>(tamperedBobPublicKey[0] ^ 0xFF);
        std::vector<unsigned char> aliceSharedSecretWithTamperedPeer(static_cast<std::size_t>(sharedSecretSize));
        int aliceTamperedSize = 0;
        const int tamperedStatus = alice.DeriveSharedSecret(&tamperedBobPublicKey[0], static_cast<int>(tamperedBobPublicKey.size()),
                                                             sharedSecretSize, &aliceSharedSecretWithTamperedPeer[0], &aliceTamperedSize);
        if (tamperedStatus == NO_ERROR && aliceSharedSecretWithTamperedPeer == aliceSharedSecret)
        {
            std::cout << "RunCryptoPPProviderKeyAgreementTest: FAILED tampered peer public key produced identical shared secret" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderKeyAgreementTest: PASSED tampered peer public key rejected or yields a different secret" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderKeyAgreementTest(void)
{
    try
    {
        CCryptoApi alice(PROVIDER_BOTAN, KEYAGREEMENT_X25519);
        CCryptoApi bob(PROVIDER_BOTAN, KEYAGREEMENT_X25519);

        int status = alice.GenerateKeyAgreementKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED alice GenerateKeyAgreementKeyPair status=" << status << std::endl;
            return status;
        }

        status = bob.GenerateKeyAgreementKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED bob GenerateKeyAgreementKeyPair status=" << status << std::endl;
            return status;
        }

        const int publicKeySize = alice.GetKeyAgreementPublicKeySize();
        if (publicKeySize != 32 || bob.GetKeyAgreementPublicKeySize() != publicKeySize)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED GetKeyAgreementPublicKeySize expected 32 alice=" << publicKeySize
                      << " bob=" << bob.GetKeyAgreementPublicKeySize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        const int sharedSecretSize = alice.GetSharedSecretSize();
        if (sharedSecretSize != 32 || bob.GetSharedSecretSize() != sharedSecretSize)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED GetSharedSecretSize expected 32 alice=" << sharedSecretSize
                      << " bob=" << bob.GetSharedSecretSize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> alicePublicKey(static_cast<std::size_t>(publicKeySize));
        int aliceActualPublicKeySize = 0;
        status = alice.ExportKeyAgreementPublicKey(publicKeySize, &alicePublicKey[0], &aliceActualPublicKeySize);
        if (status != NO_ERROR || aliceActualPublicKeySize != publicKeySize)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED alice ExportKeyAgreementPublicKey status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bobPublicKey(static_cast<std::size_t>(publicKeySize));
        int bobActualPublicKeySize = 0;
        status = bob.ExportKeyAgreementPublicKey(publicKeySize, &bobPublicKey[0], &bobActualPublicKeySize);
        if (status != NO_ERROR || bobActualPublicKeySize != publicKeySize)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED bob ExportKeyAgreementPublicKey status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> aliceSharedSecret(static_cast<std::size_t>(sharedSecretSize));
        int aliceSharedSecretSize = 0;
        status = alice.DeriveSharedSecret(&bobPublicKey[0], bobActualPublicKeySize, sharedSecretSize, &aliceSharedSecret[0], &aliceSharedSecretSize);
        if (status != NO_ERROR || aliceSharedSecretSize != sharedSecretSize)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED alice DeriveSharedSecret status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bobSharedSecret(static_cast<std::size_t>(sharedSecretSize));
        int bobSharedSecretSize = 0;
        status = bob.DeriveSharedSecret(&alicePublicKey[0], aliceActualPublicKeySize, sharedSecretSize, &bobSharedSecret[0], &bobSharedSecretSize);
        if (status != NO_ERROR || bobSharedSecretSize != sharedSecretSize)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED bob DeriveSharedSecret status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        if (aliceSharedSecret != bobSharedSecret)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED alice/bob shared secrets do not match" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderKeyAgreementTest: PASSED alice/bob agree on shared secret (" << sharedSecretSize << " bytes)" << std::endl;

        std::vector<unsigned char> tamperedBobPublicKey(bobPublicKey);
        tamperedBobPublicKey[0] = static_cast<unsigned char>(tamperedBobPublicKey[0] ^ 0xFF);
        std::vector<unsigned char> aliceSharedSecretWithTamperedPeer(static_cast<std::size_t>(sharedSecretSize));
        int aliceTamperedSize = 0;
        const int tamperedStatus = alice.DeriveSharedSecret(&tamperedBobPublicKey[0], static_cast<int>(tamperedBobPublicKey.size()),
                                                             sharedSecretSize, &aliceSharedSecretWithTamperedPeer[0], &aliceTamperedSize);
        if (tamperedStatus == NO_ERROR && aliceSharedSecretWithTamperedPeer == aliceSharedSecret)
        {
            std::cout << "RunBotanProviderKeyAgreementTest: FAILED tampered peer public key produced identical shared secret" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderKeyAgreementTest: PASSED tampered peer public key rejected or yields a different secret" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderKeyAgreementTest(void)
{
    try
    {
        CCryptoApi alice(PROVIDER_OPENSSL, KEYAGREEMENT_X25519);
        CCryptoApi bob(PROVIDER_OPENSSL, KEYAGREEMENT_X25519);

        int status = alice.GenerateKeyAgreementKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED alice GenerateKeyAgreementKeyPair status=" << status << std::endl;
            return status;
        }

        status = bob.GenerateKeyAgreementKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED bob GenerateKeyAgreementKeyPair status=" << status << std::endl;
            return status;
        }

        const int publicKeySize = alice.GetKeyAgreementPublicKeySize();
        if (publicKeySize != 32 || bob.GetKeyAgreementPublicKeySize() != publicKeySize)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED GetKeyAgreementPublicKeySize expected 32 alice=" << publicKeySize
                      << " bob=" << bob.GetKeyAgreementPublicKeySize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        const int sharedSecretSize = alice.GetSharedSecretSize();
        if (sharedSecretSize != 32 || bob.GetSharedSecretSize() != sharedSecretSize)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED GetSharedSecretSize expected 32 alice=" << sharedSecretSize
                      << " bob=" << bob.GetSharedSecretSize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> alicePublicKey(static_cast<std::size_t>(publicKeySize));
        int aliceActualPublicKeySize = 0;
        status = alice.ExportKeyAgreementPublicKey(publicKeySize, &alicePublicKey[0], &aliceActualPublicKeySize);
        if (status != NO_ERROR || aliceActualPublicKeySize != publicKeySize)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED alice ExportKeyAgreementPublicKey status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bobPublicKey(static_cast<std::size_t>(publicKeySize));
        int bobActualPublicKeySize = 0;
        status = bob.ExportKeyAgreementPublicKey(publicKeySize, &bobPublicKey[0], &bobActualPublicKeySize);
        if (status != NO_ERROR || bobActualPublicKeySize != publicKeySize)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED bob ExportKeyAgreementPublicKey status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> aliceSharedSecret(static_cast<std::size_t>(sharedSecretSize));
        int aliceSharedSecretSize = 0;
        status = alice.DeriveSharedSecret(&bobPublicKey[0], bobActualPublicKeySize, sharedSecretSize, &aliceSharedSecret[0], &aliceSharedSecretSize);
        if (status != NO_ERROR || aliceSharedSecretSize != sharedSecretSize)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED alice DeriveSharedSecret status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> bobSharedSecret(static_cast<std::size_t>(sharedSecretSize));
        int bobSharedSecretSize = 0;
        status = bob.DeriveSharedSecret(&alicePublicKey[0], aliceActualPublicKeySize, sharedSecretSize, &bobSharedSecret[0], &bobSharedSecretSize);
        if (status != NO_ERROR || bobSharedSecretSize != sharedSecretSize)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED bob DeriveSharedSecret status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        if (aliceSharedSecret != bobSharedSecret)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED alice/bob shared secrets do not match" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderKeyAgreementTest: PASSED alice/bob agree on shared secret (" << sharedSecretSize << " bytes)" << std::endl;

        std::vector<unsigned char> tamperedBobPublicKey(bobPublicKey);
        tamperedBobPublicKey[0] = static_cast<unsigned char>(tamperedBobPublicKey[0] ^ 0xFF);
        std::vector<unsigned char> aliceSharedSecretWithTamperedPeer(static_cast<std::size_t>(sharedSecretSize));
        int aliceTamperedSize = 0;
        const int tamperedStatus = alice.DeriveSharedSecret(&tamperedBobPublicKey[0], static_cast<int>(tamperedBobPublicKey.size()),
                                                             sharedSecretSize, &aliceSharedSecretWithTamperedPeer[0], &aliceTamperedSize);
        if (tamperedStatus == NO_ERROR && aliceSharedSecretWithTamperedPeer == aliceSharedSecret)
        {
            std::cout << "RunOpenSslProviderKeyAgreementTest: FAILED tampered peer public key produced identical shared secret" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderKeyAgreementTest: PASSED tampered peer public key rejected or yields a different secret" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunKeyAgreementAlgorithmsTest(void)
{
    try
    {
        struct ProviderCase
        {
            ProviderKind kind;
            const char* name;
        };

        const ProviderCase providerCases[] =
        {
            { PROVIDER_MICROSOFT, "Microsoft" },
            { PROVIDER_CRYPTOPP,  "CryptoPP" },
            { PROVIDER_BOTAN,     "Botan" },
            { PROVIDER_OPENSSL,   "OpenSSL" }
        };

        struct KeyAgreementCase
        {
            KeyAgreementAlgorithm algorithm;
            const char* name;
        };

        const KeyAgreementCase keyAgreementCases[] =
        {
            { KEYAGREEMENT_ECDH_P256, "ECDH_P256" },
            { KEYAGREEMENT_X25519,    "X25519" }
        };

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t providerIndex = 0; providerIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++providerIndex)
        {
            const ProviderKind kind = providerCases[providerIndex].kind;
            const char* providerName = providerCases[providerIndex].name;

            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
            if (!factory)
            {
                std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "] CreateProviderFactory" << std::endl;
                ++failures;
                continue;
            }

            for (std::size_t algIndex = 0; algIndex < sizeof(keyAgreementCases) / sizeof(keyAgreementCases[0]); ++algIndex)
            {
                const KeyAgreementAlgorithm algorithm = keyAgreementCases[algIndex].algorithm;
                const char* algorithmName = keyAgreementCases[algIndex].name;
                const bool supported = factory->SupportsKeyAgreementAlgorithm(algorithm);

                CCryptoApi alice(kind, algorithm);
                CCryptoApi bob(kind, algorithm);
                const int aliceKeyPairStatus = alice.GenerateKeyAgreementKeyPair();
                const int bobKeyPairStatus = bob.GenerateKeyAgreementKeyPair();

                if (!supported)
                {
                    if (aliceKeyPairStatus == NO_ERROR && bobKeyPairStatus == NO_ERROR)
                    {
                        std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                                  << "] expected unsupported but GenerateKeyAgreementKeyPair succeeded" << std::endl;
                        ++failures;
                    }
                    else
                    {
                        std::cout << "RunKeyAgreementAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                                  << "] correctly unsupported" << std::endl;
                    }
                    continue;
                }

                ++supportedCount;

                if (aliceKeyPairStatus != NO_ERROR || bobKeyPairStatus != NO_ERROR)
                {
                    std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] GenerateKeyAgreementKeyPair alice=" << aliceKeyPairStatus << " bob=" << bobKeyPairStatus
                              << " for a supported algorithm" << std::endl;
                    ++failures;
                    continue;
                }

                const int publicKeySize = alice.GetKeyAgreementPublicKeySize();
                const int sharedSecretSize = alice.GetSharedSecretSize();
                if (publicKeySize <= 0 || sharedSecretSize <= 0 ||
                    bob.GetKeyAgreementPublicKeySize() != publicKeySize || bob.GetSharedSecretSize() != sharedSecretSize)
                {
                    std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] GetKeyAgreementPublicKeySize=" << publicKeySize << " GetSharedSecretSize=" << sharedSecretSize << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> alicePublicKey(static_cast<std::size_t>(publicKeySize));
                int aliceActualPublicKeySize = 0;
                int status = alice.ExportKeyAgreementPublicKey(publicKeySize, &alicePublicKey[0], &aliceActualPublicKeySize);
                if (status != NO_ERROR || aliceActualPublicKeySize != publicKeySize)
                {
                    std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] alice ExportKeyAgreementPublicKey status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> bobPublicKey(static_cast<std::size_t>(publicKeySize));
                int bobActualPublicKeySize = 0;
                status = bob.ExportKeyAgreementPublicKey(publicKeySize, &bobPublicKey[0], &bobActualPublicKeySize);
                if (status != NO_ERROR || bobActualPublicKeySize != publicKeySize)
                {
                    std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] bob ExportKeyAgreementPublicKey status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> aliceSharedSecret(static_cast<std::size_t>(sharedSecretSize));
                int aliceSharedSecretSize = 0;
                status = alice.DeriveSharedSecret(&bobPublicKey[0], bobActualPublicKeySize, sharedSecretSize, &aliceSharedSecret[0], &aliceSharedSecretSize);
                if (status != NO_ERROR || aliceSharedSecretSize != sharedSecretSize)
                {
                    std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] alice DeriveSharedSecret status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> bobSharedSecret(static_cast<std::size_t>(sharedSecretSize));
                int bobSharedSecretSize = 0;
                status = bob.DeriveSharedSecret(&alicePublicKey[0], aliceActualPublicKeySize, sharedSecretSize, &bobSharedSecret[0], &bobSharedSecretSize);
                if (status != NO_ERROR || bobSharedSecretSize != sharedSecretSize)
                {
                    std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] bob DeriveSharedSecret status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                if (aliceSharedSecret != bobSharedSecret)
                {
                    std::cout << "RunKeyAgreementAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] alice/bob shared secrets do not match" << std::endl;
                    ++failures;
                    continue;
                }

                std::cout << "RunKeyAgreementAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                          << "] shared secret (" << sharedSecretSize << " bytes)" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunKeyAgreementAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and agreed)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunKeyAgreementAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunAESTests(void)
{
    try
    {
        // Written deliberately WITHOUT a for/while loop over the algorithm lists (unlike
        // RunSignatureAlgorithmsTest/RunKeyAgreementAlgorithmsTest above): every one of the 28 AES
        // algorithm/mode/key-size combinations (13 AEAD + 15 Legacy) x 4 providers = 112 literal
        // blocks below, each showing exactly which CCryptoApi constructor argument selects that
        // combination. Support/non-support per block is taken directly from each
        // C*Provider.cpp's own AeadAlgorithmName/LegacyAlgorithmName switch (not guessed) -- see
        // AlgorithmCapabilityMatrix.h and ccryptoapi_key_agreement_support memory for the same
        // matrix cross-checked independently.
        const char* password = "RunAESTests P@ssw0rd!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        const unsigned char plaintext[] = "RunAESTests AES parameter matrix plaintext payload.";
        const int plaintextSize = static_cast<int>(sizeof(plaintext) - 1);

        int failures = 0;

        // ============================================================================
        // Microsoft -- AEAD (AES only)
        // ============================================================================

        // Microsoft/AEAD_AES_128_GCM -- AES-128-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_128_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_128_GCM] key=128 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_128_GCM] key=128 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_192_GCM -- AES-192-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_192_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_192_GCM] key=192 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_192_GCM] key=192 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_256_GCM -- AES-256-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_256_GCM] key=256 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_256_GCM] key=256 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_128_CCM -- AES-128-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_128_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_128_CCM] key=128 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_128_CCM] key=128 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_192_CCM -- AES-192-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_192_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_192_CCM] key=192 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_192_CCM] key=192 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_256_CCM -- AES-256-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_256_CCM] key=256 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_256_CCM] key=256 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_128_EAX -- AES-128-EAX (AEAD) -- expected unsupported: CNG has no EAX chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_128_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_128_EAX] key=128 mode=EAX expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_128_EAX] key=128 mode=EAX correctly unsupported" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_192_EAX -- AES-192-EAX (AEAD) -- expected unsupported: CNG has no EAX chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_192_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_192_EAX] key=192 mode=EAX expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_192_EAX] key=192 mode=EAX correctly unsupported" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_256_EAX -- AES-256-EAX (AEAD) -- expected unsupported: CNG has no EAX chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_256_EAX] key=256 mode=EAX expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_256_EAX] key=256 mode=EAX correctly unsupported" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_128_SIV -- AES-128-SIV (AEAD) -- expected unsupported: CNG has no SIV chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_128_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_128_SIV] key=128 mode=SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_128_SIV] key=128 mode=SIV correctly unsupported" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_256_SIV -- AES-256-SIV (AEAD) -- expected unsupported: CNG has no SIV chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_256_SIV] key=256 mode=SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_256_SIV] key=256 mode=SIV correctly unsupported" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_128_GCM_SIV -- AES-128-GCM-SIV (AEAD) -- expected unsupported: CNG has no GCM-SIV chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_128_GCM_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_128_GCM_SIV] key=128 mode=GCM-SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_128_GCM_SIV] key=128 mode=GCM-SIV correctly unsupported" << std::endl;
            }
        }

        // Microsoft/AEAD_AES_256_GCM_SIV -- AES-256-GCM-SIV (AEAD) -- expected unsupported: CNG has no GCM-SIV chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, AEAD_AES_256_GCM_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/AEAD_AES_256_GCM_SIV] key=256 mode=GCM-SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/AEAD_AES_256_GCM_SIV] key=256 mode=GCM-SIV correctly unsupported" << std::endl;
            }
        }

        // ============================================================================
        // Microsoft -- Legacy (AES only)
        // ============================================================================

        // Microsoft/LEGACY_AES_128_CBC -- AES-128-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_128_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_128_CBC] key=128 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_128_CBC] key=128 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_192_CBC -- AES-192-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_192_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_192_CBC] key=192 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_192_CBC] key=192 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_256_CBC -- AES-256-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_256_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_256_CBC] key=256 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_256_CBC] key=256 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_128_CTR -- AES-128-CTR (Legacy) -- expected unsupported: CNG has no CTR chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_128_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_128_CTR] key=128 mode=CTR expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_128_CTR] key=128 mode=CTR correctly unsupported" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_192_CTR -- AES-192-CTR (Legacy) -- expected unsupported: CNG has no CTR chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_192_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_192_CTR] key=192 mode=CTR expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_192_CTR] key=192 mode=CTR correctly unsupported" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_256_CTR -- AES-256-CTR (Legacy) -- expected unsupported: CNG has no CTR chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_256_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_256_CTR] key=256 mode=CTR expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_256_CTR] key=256 mode=CTR correctly unsupported" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_128_CFB -- AES-128-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_128_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_128_CFB] key=128 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_128_CFB] key=128 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_192_CFB -- AES-192-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_192_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_192_CFB] key=192 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_192_CFB] key=192 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_256_CFB -- AES-256-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_256_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_256_CFB] key=256 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_256_CFB] key=256 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_128_OFB -- AES-128-OFB (Legacy) -- expected unsupported: CNG has no OFB chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_128_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_128_OFB] key=128 mode=OFB expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_128_OFB] key=128 mode=OFB correctly unsupported" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_192_OFB -- AES-192-OFB (Legacy) -- expected unsupported: CNG has no OFB chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_192_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_192_OFB] key=192 mode=OFB expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_192_OFB] key=192 mode=OFB correctly unsupported" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_256_OFB -- AES-256-OFB (Legacy) -- expected unsupported: CNG has no OFB chaining mode
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_256_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_256_OFB] key=256 mode=OFB expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_256_OFB] key=256 mode=OFB correctly unsupported" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_128_ECB -- AES-128-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_128_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_128_ECB] key=128 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_128_ECB] key=128 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_192_ECB -- AES-192-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_192_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_192_ECB] key=192 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_192_ECB] key=192 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Microsoft/LEGACY_AES_256_ECB -- AES-256-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_MICROSOFT, LEGACY_AES_256_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Microsoft/LEGACY_AES_256_ECB] key=256 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Microsoft/LEGACY_AES_256_ECB] key=256 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // ============================================================================
        // CryptoPP -- AEAD (AES only)
        // ============================================================================

        // CryptoPP/AEAD_AES_128_GCM -- AES-128-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_128_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_128_GCM] key=128 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_128_GCM] key=128 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_192_GCM -- AES-192-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_192_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_192_GCM] key=192 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_192_GCM] key=192 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_256_GCM -- AES-256-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_256_GCM] key=256 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_256_GCM] key=256 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_128_CCM -- AES-128-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_128_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_128_CCM] key=128 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_128_CCM] key=128 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_192_CCM -- AES-192-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_192_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_192_CCM] key=192 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_192_CCM] key=192 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_256_CCM -- AES-256-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_256_CCM] key=256 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_256_CCM] key=256 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_128_EAX -- AES-128-EAX (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_128_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_128_EAX] key=128 mode=EAX status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_128_EAX] key=128 mode=EAX round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_192_EAX -- AES-192-EAX (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_192_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_192_EAX] key=192 mode=EAX status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_192_EAX] key=192 mode=EAX round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_256_EAX -- AES-256-EAX (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_256_EAX] key=256 mode=EAX status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_256_EAX] key=256 mode=EAX round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_128_SIV -- AES-128-SIV (AEAD) -- expected unsupported: CryptoPP 8.9.0 has no built-in SIV mode
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_128_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_128_SIV] key=128 mode=SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_128_SIV] key=128 mode=SIV correctly unsupported" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_256_SIV -- AES-256-SIV (AEAD) -- expected unsupported: CryptoPP 8.9.0 has no built-in SIV mode
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_256_SIV] key=256 mode=SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_256_SIV] key=256 mode=SIV correctly unsupported" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_128_GCM_SIV -- AES-128-GCM-SIV (AEAD) -- expected unsupported: CryptoPP 8.9.0 has no built-in AES-GCM-SIV mode
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_128_GCM_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_128_GCM_SIV] key=128 mode=GCM-SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_128_GCM_SIV] key=128 mode=GCM-SIV correctly unsupported" << std::endl;
            }
        }

        // CryptoPP/AEAD_AES_256_GCM_SIV -- AES-256-GCM-SIV (AEAD) -- expected unsupported: CryptoPP 8.9.0 has no built-in AES-GCM-SIV mode
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, AEAD_AES_256_GCM_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/AEAD_AES_256_GCM_SIV] key=256 mode=GCM-SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/AEAD_AES_256_GCM_SIV] key=256 mode=GCM-SIV correctly unsupported" << std::endl;
            }
        }

        // ============================================================================
        // CryptoPP -- Legacy (AES only)
        // ============================================================================

        // CryptoPP/LEGACY_AES_128_CBC -- AES-128-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_128_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_128_CBC] key=128 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_128_CBC] key=128 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_192_CBC -- AES-192-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_192_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_192_CBC] key=192 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_192_CBC] key=192 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_256_CBC -- AES-256-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_256_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_256_CBC] key=256 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_256_CBC] key=256 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_128_CTR -- AES-128-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_128_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_128_CTR] key=128 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_128_CTR] key=128 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_192_CTR -- AES-192-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_192_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_192_CTR] key=192 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_192_CTR] key=192 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_256_CTR -- AES-256-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_256_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_256_CTR] key=256 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_256_CTR] key=256 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_128_CFB -- AES-128-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_128_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_128_CFB] key=128 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_128_CFB] key=128 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_192_CFB -- AES-192-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_192_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_192_CFB] key=192 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_192_CFB] key=192 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_256_CFB -- AES-256-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_256_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_256_CFB] key=256 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_256_CFB] key=256 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_128_OFB -- AES-128-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_128_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_128_OFB] key=128 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_128_OFB] key=128 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_192_OFB -- AES-192-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_192_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_192_OFB] key=192 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_192_OFB] key=192 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_256_OFB -- AES-256-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_256_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_256_OFB] key=256 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_256_OFB] key=256 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_128_ECB -- AES-128-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_128_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_128_ECB] key=128 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_128_ECB] key=128 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_192_ECB -- AES-192-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_192_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_192_ECB] key=192 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_192_ECB] key=192 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // CryptoPP/LEGACY_AES_256_ECB -- AES-256-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_CRYPTOPP, LEGACY_AES_256_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [CryptoPP/LEGACY_AES_256_ECB] key=256 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [CryptoPP/LEGACY_AES_256_ECB] key=256 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // ============================================================================
        // Botan -- AEAD (AES only)
        // ============================================================================

        // Botan/AEAD_AES_128_GCM -- AES-128-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_128_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_128_GCM] key=128 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_128_GCM] key=128 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_192_GCM -- AES-192-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_192_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_192_GCM] key=192 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_192_GCM] key=192 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_256_GCM -- AES-256-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_256_GCM] key=256 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_256_GCM] key=256 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_128_CCM -- AES-128-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_128_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_128_CCM] key=128 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_128_CCM] key=128 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_192_CCM -- AES-192-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_192_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_192_CCM] key=192 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_192_CCM] key=192 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_256_CCM -- AES-256-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_256_CCM] key=256 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_256_CCM] key=256 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_128_EAX -- AES-128-EAX (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_128_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_128_EAX] key=128 mode=EAX status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_128_EAX] key=128 mode=EAX round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_192_EAX -- AES-192-EAX (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_192_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_192_EAX] key=192 mode=EAX status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_192_EAX] key=192 mode=EAX round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_256_EAX -- AES-256-EAX (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_256_EAX] key=256 mode=EAX status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_256_EAX] key=256 mode=EAX round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_128_SIV -- AES-128-SIV (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_128_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_128_SIV] key=128 mode=SIV status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_128_SIV] key=128 mode=SIV round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_256_SIV -- AES-256-SIV (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_256_SIV] key=256 mode=SIV status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_256_SIV] key=256 mode=SIV round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_128_GCM_SIV -- AES-128-GCM-SIV (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_128_GCM_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_128_GCM_SIV] key=128 mode=GCM-SIV status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_128_GCM_SIV] key=128 mode=GCM-SIV round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/AEAD_AES_256_GCM_SIV -- AES-256-GCM-SIV (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, AEAD_AES_256_GCM_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/AEAD_AES_256_GCM_SIV] key=256 mode=GCM-SIV status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/AEAD_AES_256_GCM_SIV] key=256 mode=GCM-SIV round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // ============================================================================
        // Botan -- Legacy (AES only)
        // ============================================================================

        // Botan/LEGACY_AES_128_CBC -- AES-128-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_128_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_128_CBC] key=128 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_128_CBC] key=128 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_192_CBC -- AES-192-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_192_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_192_CBC] key=192 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_192_CBC] key=192 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_256_CBC -- AES-256-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_256_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_256_CBC] key=256 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_256_CBC] key=256 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_128_CTR -- AES-128-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_128_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_128_CTR] key=128 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_128_CTR] key=128 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_192_CTR -- AES-192-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_192_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_192_CTR] key=192 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_192_CTR] key=192 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_256_CTR -- AES-256-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_256_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_256_CTR] key=256 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_256_CTR] key=256 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_128_CFB -- AES-128-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_128_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_128_CFB] key=128 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_128_CFB] key=128 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_192_CFB -- AES-192-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_192_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_192_CFB] key=192 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_192_CFB] key=192 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_256_CFB -- AES-256-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_256_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_256_CFB] key=256 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_256_CFB] key=256 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_128_OFB -- AES-128-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_128_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_128_OFB] key=128 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_128_OFB] key=128 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_192_OFB -- AES-192-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_192_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_192_OFB] key=192 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_192_OFB] key=192 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_256_OFB -- AES-256-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_256_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_256_OFB] key=256 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_256_OFB] key=256 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // Botan/LEGACY_AES_128_ECB -- AES-128-ECB (Legacy) -- expected unsupported: Botan 3.x has no standalone ECB Cipher_Mode factory entry
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_128_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_128_ECB] key=128 mode=ECB expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_128_ECB] key=128 mode=ECB correctly unsupported" << std::endl;
            }
        }

        // Botan/LEGACY_AES_192_ECB -- AES-192-ECB (Legacy) -- expected unsupported: Botan 3.x has no standalone ECB Cipher_Mode factory entry
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_192_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_192_ECB] key=192 mode=ECB expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_192_ECB] key=192 mode=ECB correctly unsupported" << std::endl;
            }
        }

        // Botan/LEGACY_AES_256_ECB -- AES-256-ECB (Legacy) -- expected unsupported: Botan 3.x has no standalone ECB Cipher_Mode factory entry
        {
            CCryptoApi cryptoApi(PROVIDER_BOTAN, LEGACY_AES_256_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                             static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [Botan/LEGACY_AES_256_ECB] key=256 mode=ECB expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [Botan/LEGACY_AES_256_ECB] key=256 mode=ECB correctly unsupported" << std::endl;
            }
        }

        // ============================================================================
        // OpenSSL -- AEAD (AES only)
        // ============================================================================

        // OpenSSL/AEAD_AES_128_GCM -- AES-128-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_128_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_128_GCM] key=128 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_128_GCM] key=128 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_192_GCM -- AES-192-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_192_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_192_GCM] key=192 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_192_GCM] key=192 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_256_GCM -- AES-256-GCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_256_GCM] key=256 mode=GCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_256_GCM] key=256 mode=GCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_128_CCM -- AES-128-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_128_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_128_CCM] key=128 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_128_CCM] key=128 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_192_CCM -- AES-192-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_192_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_192_CCM] key=192 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_192_CCM] key=192 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_256_CCM -- AES-256-CCM (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_CCM);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_256_CCM] key=256 mode=CCM status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_256_CCM] key=256 mode=CCM round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_128_EAX -- AES-128-EAX (AEAD) -- expected unsupported: EAX never existed in OpenSSL
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_128_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_128_EAX] key=128 mode=EAX expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_128_EAX] key=128 mode=EAX correctly unsupported" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_192_EAX -- AES-192-EAX (AEAD) -- expected unsupported: EAX never existed in OpenSSL
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_192_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_192_EAX] key=192 mode=EAX expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_192_EAX] key=192 mode=EAX correctly unsupported" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_256_EAX -- AES-256-EAX (AEAD) -- expected unsupported: EAX never existed in OpenSSL
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_EAX);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_256_EAX] key=256 mode=EAX expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_256_EAX] key=256 mode=EAX correctly unsupported" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_128_SIV -- AES-128-SIV (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_128_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_128_SIV] key=128 mode=SIV status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_128_SIV] key=128 mode=SIV round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_256_SIV -- AES-256-SIV (AEAD)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                 static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                 nullptr, nullptr);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                 static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize,
                                                 nullptr, nullptr);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_256_SIV] key=256 mode=SIV status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_256_SIV] key=256 mode=SIV round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_128_GCM_SIV -- AES-128-GCM-SIV (AEAD) -- expected unsupported: AES-GCM-SIV is not wired in OpenSSL's EVP cipher list here
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_128_GCM_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_128_GCM_SIV] key=128 mode=GCM-SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_128_GCM_SIV] key=128 mode=GCM-SIV correctly unsupported" << std::endl;
            }
        }

        // OpenSSL/AEAD_AES_256_GCM_SIV -- AES-256-GCM-SIV (AEAD) -- expected unsupported: AES-GCM-SIV is not wired in OpenSSL's EVP cipher list here
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, AEAD_AES_256_GCM_SIV);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            const int status = cryptoApi.EncryptBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize,
                                                       nullptr, nullptr);
            if (status == NO_ERROR)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/AEAD_AES_256_GCM_SIV] key=256 mode=GCM-SIV expected unsupported but Encrypt succeeded" << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/AEAD_AES_256_GCM_SIV] key=256 mode=GCM-SIV correctly unsupported" << std::endl;
            }
        }

        // ============================================================================
        // OpenSSL -- Legacy (AES only)
        // ============================================================================

        // OpenSSL/LEGACY_AES_128_CBC -- AES-128-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_128_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_128_CBC] key=128 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_128_CBC] key=128 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_192_CBC -- AES-192-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_192_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_192_CBC] key=192 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_192_CBC] key=192 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_256_CBC -- AES-256-CBC (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_256_CBC);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_256_CBC] key=256 mode=CBC status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_256_CBC] key=256 mode=CBC round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_128_CTR -- AES-128-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_128_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_128_CTR] key=128 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_128_CTR] key=128 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_192_CTR -- AES-192-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_192_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_192_CTR] key=192 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_192_CTR] key=192 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_256_CTR -- AES-256-CTR (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_256_CTR);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_256_CTR] key=256 mode=CTR status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_256_CTR] key=256 mode=CTR round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_128_CFB -- AES-128-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_128_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_128_CFB] key=128 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_128_CFB] key=128 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_192_CFB -- AES-192-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_192_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_192_CFB] key=192 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_192_CFB] key=192 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_256_CFB -- AES-256-CFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_256_CFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_256_CFB] key=256 mode=CFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_256_CFB] key=256 mode=CFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_128_OFB -- AES-128-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_128_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_128_OFB] key=128 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_128_OFB] key=128 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_192_OFB -- AES-192-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_192_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_192_OFB] key=192 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_192_OFB] key=192 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_256_OFB -- AES-256-OFB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_256_OFB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_256_OFB] key=256 mode=OFB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_256_OFB] key=256 mode=OFB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_128_ECB -- AES-128-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_128_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_128_ECB] key=128 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_128_ECB] key=128 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_192_ECB -- AES-192-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_192_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_192_ECB] key=192 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_192_ECB] key=192 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        // OpenSSL/LEGACY_AES_256_ECB -- AES-256-ECB (Legacy)
        {
            CCryptoApi cryptoApi(PROVIDER_OPENSSL, LEGACY_AES_256_ECB);
            std::vector<unsigned char> ciphertext(plaintextSize + 128);
            int ciphertextSize = 0;
            int status = cryptoApi.EncryptLegacyBuffer(password, passwordSize, plaintext, plaintextSize,
                                                       static_cast<int>(ciphertext.size()), &ciphertext[0], &ciphertextSize);
            std::vector<unsigned char> decrypted(plaintextSize + 128);
            int decryptedSize = 0;
            if (status == NO_ERROR)
            {
                status = cryptoApi.DecryptLegacyBuffer(password, passwordSize, &ciphertext[0], ciphertextSize,
                                                       static_cast<int>(decrypted.size()), &decrypted[0], &decryptedSize);
            }
            if (status != NO_ERROR || decryptedSize != plaintextSize || std::memcmp(&decrypted[0], plaintext, plaintextSize) != 0)
            {
                std::cout << "RunAESTests: FAILED [OpenSSL/LEGACY_AES_256_ECB] key=256 mode=ECB status=" << status << std::endl;
                ++failures;
            }
            else
            {
                std::cout << "RunAESTests: PASSED [OpenSSL/LEGACY_AES_256_ECB] key=256 mode=ECB round-trip (" << ciphertextSize << " bytes)" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunAESTests: PASSED (112 combinations checked, 87 supported+round-tripped, 25 correctly-unsupported)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunAESTests: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunSharedInstanceTest(void)
{
    try
    {
        CCryptoApi::ResetShared();

        CCryptoApi& first = CCryptoApi::GetShared(PROVIDER_MICROSOFT, SIGNATURE_ECDSA_P256_SHA256);
        CCryptoApi& second = CCryptoApi::GetShared(PROVIDER_MICROSOFT, SIGNATURE_ECDSA_P256_SHA256);
        if (&first != &second)
        {
            std::cout << "RunSharedInstanceTest: FAILED same-config GetShared returned different instances" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunSharedInstanceTest: PASSED same-config GetShared returns identical instance" << std::endl;

        CCryptoApi& different = CCryptoApi::GetShared(PROVIDER_OPENSSL, SIGNATURE_ECDSA_P256_SHA256);
        if (&different == &first)
        {
            std::cout << "RunSharedInstanceTest: FAILED different-config GetShared returned the same instance" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunSharedInstanceTest: PASSED different-config GetShared returns a different instance" << std::endl;

        int status = first.GenerateSignatureKeyPair();
        if (status != NO_ERROR)
        {
            std::cout << "RunSharedInstanceTest: FAILED GenerateSignatureKeyPair status=" << status << std::endl;
            return status;
        }

        const int signatureSize = second.GetSignatureSize();
        if (signatureSize != 64)
        {
            std::cout << "RunSharedInstanceTest: FAILED second reference did not see the key pair generated through first, GetSignatureSize=" << signatureSize << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* message = "RunSharedInstanceTest message to sign";
        const int messageSize = static_cast<int>(std::strlen(message));
        const unsigned char* messageBytes = reinterpret_cast<const unsigned char*>(message);

        std::vector<unsigned char> signature(static_cast<std::size_t>(signatureSize));
        int actualSignatureSize = 0;
        status = first.SignBuffer(messageBytes, messageSize, signatureSize, &signature[0], &actualSignatureSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunSharedInstanceTest: FAILED SignBuffer via first status=" << status << std::endl;
            return status;
        }

        bool isValid = false;
        status = second.VerifyBuffer(messageBytes, messageSize, &signature[0], actualSignatureSize, &isValid);
        if (status != NO_ERROR || !isValid)
        {
            std::cout << "RunSharedInstanceTest: FAILED VerifyBuffer via second (same shared key pair) status=" << status << " valid=" << isValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunSharedInstanceTest: PASSED key pair generated via one reference is visible/usable via another reference to the same shared instance" << std::endl;

        CCryptoApi::ResetShared();

        CCryptoApi& afterReset = CCryptoApi::GetShared(PROVIDER_MICROSOFT, SIGNATURE_ECDSA_P256_SHA256);
        if (afterReset.GetSignatureSize() != 0)
        {
            std::cout << "RunSharedInstanceTest: FAILED instance after ResetShared still has a key pair, GetSignatureSize=" << afterReset.GetSignatureSize() << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunSharedInstanceTest: PASSED ResetShared discards cached instances (fresh instance has no key pair)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunRandomAlgorithmsTest(void)
{
    try
    {
        struct ProviderCase
        {
            ProviderKind kind;
            const char* name;
        };

        const ProviderCase providerCases[] =
        {
            { PROVIDER_MICROSOFT, "Microsoft" },
            { PROVIDER_CRYPTOPP,  "CryptoPP" },
            { PROVIDER_BOTAN,     "Botan" },
            { PROVIDER_OPENSSL,   "OpenSSL" }
        };

        struct RandomCase
        {
            RandomAlgorithm algorithm;
            const char* name;
        };

        const RandomCase randomCases[] =
        {
            { RANDOM_SYSTEM,    "SYSTEM" },
            { RANDOM_HASH_DRBG, "HASH_DRBG" },
            { RANDOM_HMAC_DRBG, "HMAC_DRBG" },
            { RANDOM_CTR_DRBG,  "CTR_DRBG" }
        };

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t providerIndex = 0; providerIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++providerIndex)
        {
            const ProviderKind kind = providerCases[providerIndex].kind;
            const char* providerName = providerCases[providerIndex].name;

            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
            if (!factory)
            {
                std::cout << "RunRandomAlgorithmsTest: FAILED [" << providerName << "] CreateProviderFactory" << std::endl;
                ++failures;
                continue;
            }

            for (std::size_t algIndex = 0; algIndex < sizeof(randomCases) / sizeof(randomCases[0]); ++algIndex)
            {
                const RandomAlgorithm algorithm = randomCases[algIndex].algorithm;
                const char* algorithmName = randomCases[algIndex].name;
                const bool supported = factory->SupportsRandomAlgorithm(algorithm);

                CCryptoApi cryptoApi(kind, AEAD_AES_256_GCM);

                std::vector<unsigned char> output1(32);
                int status = cryptoApi.GenerateRandomBytes(algorithm, &output1[0], static_cast<int>(output1.size()));

                if (!supported)
                {
                    if (status == NO_ERROR)
                    {
                        std::cout << "RunRandomAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                                  << "] expected unsupported but GenerateRandomBytes succeeded" << std::endl;
                        ++failures;
                    }
                    else
                    {
                        std::cout << "RunRandomAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                                  << "] correctly unsupported" << std::endl;
                    }
                    continue;
                }

                ++supportedCount;

                if (status != NO_ERROR)
                {
                    std::cout << "RunRandomAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] GenerateRandomBytes status=" << status << " for a supported algorithm" << std::endl;
                    ++failures;
                    continue;
                }

                std::vector<unsigned char> output2(32);
                status = cryptoApi.GenerateRandomBytes(algorithm, &output2[0], static_cast<int>(output2.size()));
                if (status != NO_ERROR)
                {
                    std::cout << "RunRandomAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] second GenerateRandomBytes status=" << status << std::endl;
                    ++failures;
                    continue;
                }

                if (output1 == output2)
                {
                    std::cout << "RunRandomAlgorithmsTest: FAILED [" << providerName << "/" << algorithmName
                              << "] two independent calls produced identical output" << std::endl;
                    ++failures;
                    continue;
                }

                std::cout << "RunRandomAlgorithmsTest: PASSED [" << providerName << "/" << algorithmName
                          << "] two independent calls produced different output (32 bytes each)" << std::endl;
            }
        }

        if (failures == 0)
        {
            std::cout << "RunRandomAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and generated distinct output)" << std::endl;
            return NO_ERROR;
        }

        std::cout << "RunRandomAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptStringMultilingualTest(void)
{
    try
    {
        const char* password = "MultiLangTestPass123!";
        const int passwordSize = static_cast<int>(std::strlen(password));

        const char* englishText = "The quick brown fox jumps over the lazy dog.";
        const char* turkishText = "Pijamal\xC4\xB1 hasta ya\xC4\x9F\xC4\xB1z \xC5\x9Fof\xC3\xB6re \xC3\xA7" "abucak g\xC3\xBCvendi.";
        const char* japaneseText = "\xE3\x81\x93\xE3\x82\x93\xE3\x81\xAB\xE3\x81\xA1\xE3\x81\xAF\xE4\xB8\x96\xE7\x95\x8C";
        const char* russianText = "\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82, \xD0\xBC\xD0\xB8\xD1\x80! "
                                   "\xD0\x9A\xD0\xB0\xD0\xBA \xD0\xB4\xD0\xB5\xD0\xBB\xD0\xB0?";
        const char* chineseText = "\xE4\xBD\xA0\xE5\xA5\xBD\xEF\xBC\x8C\xE4\xB8\x96\xE7\x95\x8C";
        const char* greekText = "\xCE\x93\xCE\xB5\xCE\xB9\xCE\xB1 \xCF\x83\xCE\xBF\xCF\x85 \xCE\xBA\xCF\x8C\xCF\x83\xCE\xBC\xCE\xB5";

        struct LanguageCase
        {
            const char* label;
            const char* text;
        };

        const LanguageCase languageCases[] =
        {
            { "English", englishText },
            { "Turkish", turkishText },
            { "Japanese", japaneseText },
            { "Russian", russianText },
            { "Chinese", chineseText },
            { "Greek", greekText }
        };

        CCryptoApi cryptoApi;

        for (std::size_t caseIndex = 0; caseIndex < sizeof(languageCases) / sizeof(languageCases[0]); ++caseIndex)
        {
            const char* label = languageCases[caseIndex].label;
            const char* text = languageCases[caseIndex].text;
            const int textSize = static_cast<int>(std::strlen(text));

            int requiredEncryptSize = 0;
            int status = cryptoApi.EncryptString(password, passwordSize, text, textSize,
                                                 0, nullptr, &requiredEncryptSize,
                                                 nullptr, nullptr);
            if (status != BUFFER_TOO_SMALL)
            {
                std::cout << "RunEncryptStringMultilingualTest: FAILED " << label
                          << " encrypt size query status=" << status << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::vector<unsigned char> encryptedData(requiredEncryptSize);
            int encryptedSize = 0;
            status = cryptoApi.EncryptString(password, passwordSize, text, textSize,
                                             requiredEncryptSize, &encryptedData[0], &encryptedSize,
                                             nullptr, nullptr);
            if (status != NO_ERROR)
            {
                std::cout << "RunEncryptStringMultilingualTest: FAILED " << label
                          << " EncryptString status=" << status << std::endl;
                return status;
            }

            int requiredDecryptSize = 0;
            status = cryptoApi.DecryptString(password, passwordSize,
                                             &encryptedData[0], encryptedSize,
                                             0, nullptr, &requiredDecryptSize,
                                             nullptr, nullptr);
            if (status != BUFFER_TOO_SMALL)
            {
                std::cout << "RunEncryptStringMultilingualTest: FAILED " << label
                          << " decrypt size query status=" << status << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::vector<char> decryptedText(requiredDecryptSize);
            int decryptedSize = 0;
            status = cryptoApi.DecryptString(password, passwordSize,
                                             &encryptedData[0], encryptedSize,
                                             requiredDecryptSize,
                                             decryptedText.empty() ? nullptr : &decryptedText[0], &decryptedSize,
                                             nullptr, nullptr);
            if (status != NO_ERROR)
            {
                std::cout << "RunEncryptStringMultilingualTest: FAILED " << label
                          << " DecryptString status=" << status << std::endl;
                return status;
            }

            if (decryptedSize != textSize ||
                std::memcmp(&decryptedText[0], text, static_cast<std::size_t>(textSize)) != 0)
            {
                std::cout << "RunEncryptStringMultilingualTest: FAILED " << label << " content mismatch" << std::endl;
                return UNEXPECTED_ERROR;
            }

            std::cout << "RunEncryptStringMultilingualTest: PASSED " << label
                      << " (" << textSize << " bytes)" << std::endl;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPrimitiveDataTest(void)
{
    try
    {
        const char* password = "PrimitiveTestPass!";
        const int passwordSize = static_cast<int>(std::strlen(password));
        CCryptoApi cryptoApi;
        int failures = 0;

        {
            const char values[] = { 0, 1, -1, CHAR_MAX, CHAR_MIN, 'A' };
            const std::size_t valueCount = sizeof(values) / sizeof(values[0]);
            std::cout << "RunPrimitiveDataTest: testing char (" << valueCount << " values)..." << std::endl;
            for (std::size_t index = 0; index < valueCount; ++index)
            {
                char output = 0;
                const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, &values[index], 1, &output) &&
                                output == values[index];
                std::cout << "  char[" << index << "]=" << static_cast<int>(values[index])
                          << " -> " << (ok ? "OK" : "FAILED") << std::endl;
                if (!ok)
                {
                    ++failures;
                }
            }
        }

        {
            const short values[] = { 0, 1, -1, SHRT_MAX, SHRT_MIN, 12345 };
            const std::size_t valueCount = sizeof(values) / sizeof(values[0]);
            std::cout << "RunPrimitiveDataTest: testing short (" << valueCount << " values)..." << std::endl;
            for (std::size_t index = 0; index < valueCount; ++index)
            {
                short output = 0;
                const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, &values[index], 1, &output) &&
                                output == values[index];
                std::cout << "  short[" << index << "]=" << values[index]
                          << " -> " << (ok ? "OK" : "FAILED") << std::endl;
                if (!ok)
                {
                    ++failures;
                }
            }
        }

        {
            const int values[] = { 0, 1, -1, INT_MAX, INT_MIN, 123456789 };
            const std::size_t valueCount = sizeof(values) / sizeof(values[0]);
            std::cout << "RunPrimitiveDataTest: testing int (" << valueCount << " values)..." << std::endl;
            for (std::size_t index = 0; index < valueCount; ++index)
            {
                int output = 0;
                const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, &values[index], 1, &output) &&
                                output == values[index];
                std::cout << "  int[" << index << "]=" << values[index]
                          << " -> " << (ok ? "OK" : "FAILED") << std::endl;
                if (!ok)
                {
                    ++failures;
                }
            }
        }

        {
            const long values[] = { 0, 1, -1, LONG_MAX, LONG_MIN };
            const std::size_t valueCount = sizeof(values) / sizeof(values[0]);
            std::cout << "RunPrimitiveDataTest: testing long (" << valueCount << " values)..." << std::endl;
            for (std::size_t index = 0; index < valueCount; ++index)
            {
                long output = 0;
                const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, &values[index], 1, &output) &&
                                output == values[index];
                std::cout << "  long[" << index << "]=" << values[index]
                          << " -> " << (ok ? "OK" : "FAILED") << std::endl;
                if (!ok)
                {
                    ++failures;
                }
            }
        }

        {
            const float values[] =
            {
                0.0f, -0.0f, 1.5f, -1.5f,
                std::numeric_limits<float>::max(), std::numeric_limits<float>::lowest(),
                std::numeric_limits<float>::quiet_NaN(),
                std::numeric_limits<float>::infinity(), -std::numeric_limits<float>::infinity()
            };
            const std::size_t valueCount = sizeof(values) / sizeof(values[0]);
            std::cout << "RunPrimitiveDataTest: testing float (" << valueCount << " values)..." << std::endl;
            for (std::size_t index = 0; index < valueCount; ++index)
            {
                float output = 0.0f;
                const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, &values[index], 1, &output);
                std::cout << "  float[" << index << "]=" << values[index]
                          << " -> " << (ok ? "OK" : "FAILED") << std::endl;
                if (!ok)
                {
                    ++failures;
                }
            }
        }

        {
            const double values[] =
            {
                0.0, -0.0, 1.5, -1.5,
                std::numeric_limits<double>::max(), std::numeric_limits<double>::lowest(),
                std::numeric_limits<double>::quiet_NaN(),
                std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity()
            };
            const std::size_t valueCount = sizeof(values) / sizeof(values[0]);
            std::cout << "RunPrimitiveDataTest: testing double (" << valueCount << " values)..." << std::endl;
            for (std::size_t index = 0; index < valueCount; ++index)
            {
                double output = 0.0;
                const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, &values[index], 1, &output);
                std::cout << "  double[" << index << "]=" << values[index]
                          << " -> " << (ok ? "OK" : "FAILED") << std::endl;
                if (!ok)
                {
                    ++failures;
                }
            }
        }

        if (failures != 0)
        {
            std::cout << "RunPrimitiveDataTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunPrimitiveDataTest: PASSED (char, short, int, long, float, double)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPrimitiveArrayDataTest(void)
{
    try
    {
        const char* password = "PrimitiveArrayTestPass!";
        const int passwordSize = static_cast<int>(std::strlen(password));
        CCryptoApi cryptoApi;
        int failures = 0;

        {
            std::cout << "RunPrimitiveArrayDataTest: testing char[64]..." << std::endl;
            char input[64];
            for (int index = 0; index < 64; ++index)
            {
                input[index] = static_cast<char>(index - 32);
            }

            char output[64] = {};
            const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, input, 64, output);
            std::cout << "  char[64] -> " << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        {
            std::cout << "RunPrimitiveArrayDataTest: testing short[50]..." << std::endl;
            short input[50];
            for (int index = 0; index < 50; ++index)
            {
                input[index] = static_cast<short>((index - 25) * 1000);
            }
            input[0] = SHRT_MIN;
            input[49] = SHRT_MAX;

            short output[50] = {};
            const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, input, 50, output);
            std::cout << "  short[50] -> " << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        {
            std::cout << "RunPrimitiveArrayDataTest: testing int[100]..." << std::endl;
            int input[100];
            for (int index = 0; index < 100; ++index)
            {
                input[index] = (index - 50) * 1000003;
            }
            input[0] = INT_MIN;
            input[99] = INT_MAX;

            int output[100] = {};
            const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, input, 100, output);
            std::cout << "  int[100] -> " << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        {
            std::cout << "RunPrimitiveArrayDataTest: testing long[40]..." << std::endl;
            long input[40];
            for (int index = 0; index < 40; ++index)
            {
                input[index] = static_cast<long>(index - 20) * 987654321L;
            }
            input[0] = LONG_MIN;
            input[39] = LONG_MAX;

            long output[40] = {};
            const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, input, 40, output);
            std::cout << "  long[40] -> " << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        {
            std::cout << "RunPrimitiveArrayDataTest: testing float[30]..." << std::endl;
            float input[30];
            for (int index = 0; index < 30; ++index)
            {
                input[index] = static_cast<float>(index - 15) * 0.75f;
            }
            input[0] = std::numeric_limits<float>::quiet_NaN();
            input[1] = std::numeric_limits<float>::infinity();
            input[2] = -std::numeric_limits<float>::infinity();
            input[29] = std::numeric_limits<float>::max();

            float output[30] = {};
            const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, input, 30, output);
            std::cout << "  float[30] -> " << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        {
            std::cout << "RunPrimitiveArrayDataTest: testing double[30]..." << std::endl;
            double input[30];
            for (int index = 0; index < 30; ++index)
            {
                input[index] = static_cast<double>(index - 15) * 0.125;
            }
            input[0] = std::numeric_limits<double>::quiet_NaN();
            input[1] = std::numeric_limits<double>::infinity();
            input[2] = -std::numeric_limits<double>::infinity();
            input[29] = std::numeric_limits<double>::max();

            double output[30] = {};
            const bool ok = RoundTripBytes(cryptoApi, password, passwordSize, input, 30, output);
            std::cout << "  double[30] -> " << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        if (failures != 0)
        {
            std::cout << "RunPrimitiveArrayDataTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunPrimitiveArrayDataTest: PASSED (char[], short[], int[], long[], float[], double[])" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunVectorDataTest(void)
{
    try
    {
        const char* password = "VectorTestPass!";
        const int passwordSize = static_cast<int>(std::strlen(password));
        CCryptoApi cryptoApi;
        int failures = 0;

        // std::vector<std::string>: each element has no fixed size, so each one is encrypted and
        // decrypted independently via EncryptString/DecryptString (not as one contiguous buffer).
        {
            std::vector<std::string> inputStrings;
            inputStrings.push_back("Hello from a std::vector<std::string>!");
            inputStrings.push_back("\xC4\xB0kinci sat\xC4\xB1r: T\xC3\xBCrk\xC3\xA7" "e karakterler.");
            inputStrings.push_back("");
            inputStrings.push_back("Numbers: 1234567890 and symbols !@#$%.");

            std::vector<std::string> outputStrings;
            bool vectorOk = true;

            for (std::size_t index = 0; index < inputStrings.size(); ++index)
            {
                const std::string& text = inputStrings[index];
                std::string decryptedText;
                if (!EncryptDecryptStringRoundTrip(cryptoApi, password, passwordSize,
                                                   text.c_str(), static_cast<int>(text.size()), decryptedText))
                {
                    vectorOk = false;
                    break;
                }

                outputStrings.push_back(decryptedText);
            }

            const bool ok = vectorOk && outputStrings == inputStrings;
            std::cout << "RunVectorDataTest: vector<string> (" << inputStrings.size() << " elements) -> "
                      << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        // std::vector<short> and std::vector<double>: contiguous storage, so the whole vector is
        // encrypted/decrypted as a single buffer via RoundTripBytes (same helper as the array test).
        {
            std::vector<short> inputShorts;
            for (short index = 0; index < 200; ++index)
            {
                inputShorts.push_back(static_cast<short>(index * 37 - 5000));
            }
            inputShorts[0] = SHRT_MIN;
            inputShorts[inputShorts.size() - 1] = SHRT_MAX;

            std::vector<short> outputShorts(inputShorts.size());
            const bool ok = RoundTripBytes(cryptoApi, password, passwordSize,
                                           &inputShorts[0], inputShorts.size(), &outputShorts[0]);
            std::cout << "RunVectorDataTest: vector<short> (" << inputShorts.size() << " elements) -> "
                      << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        {
            std::vector<double> inputDoubles;
            for (int index = 0; index < 150; ++index)
            {
                inputDoubles.push_back(static_cast<double>(index - 75) * 0.333);
            }
            inputDoubles[0] = std::numeric_limits<double>::quiet_NaN();
            inputDoubles[1] = std::numeric_limits<double>::infinity();
            inputDoubles[2] = -std::numeric_limits<double>::infinity();

            std::vector<double> outputDoubles(inputDoubles.size());
            const bool ok = RoundTripBytes(cryptoApi, password, passwordSize,
                                           &inputDoubles[0], inputDoubles.size(), &outputDoubles[0]);
            std::cout << "RunVectorDataTest: vector<double> (" << inputDoubles.size() << " elements) -> "
                      << (ok ? "OK" : "FAILED") << std::endl;
            if (!ok)
            {
                ++failures;
            }
        }

        if (failures != 0)
        {
            std::cout << "RunVectorDataTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunVectorDataTest: PASSED (vector<string>, vector<short>, vector<double>)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunVectorWideStringDataTest(void)
{
    try
    {
        const char* password = "VectorWideStringTestPass!";
        const int passwordSize = static_cast<int>(std::strlen(password));
        CCryptoApi cryptoApi;

        std::vector<std::wstring> inputWideStrings;
        inputWideStrings.push_back(L"Hello, wide world!");
        inputWideStrings.push_back(L"\u0130stanbul, T\u00FCrkiye");
        inputWideStrings.push_back(L"");
        inputWideStrings.push_back(L"\u4F60\u597D"); // Chinese "Hello"

        std::vector<std::wstring> outputWideStrings;
        bool vectorOk = true;

        for (std::size_t index = 0; index < inputWideStrings.size(); ++index)
        {
            std::string utf8Text;
            if (!ConvertWideToUtf8(inputWideStrings[index], utf8Text))
            {
                vectorOk = false;
                break;
            }

            std::string decryptedUtf8;
            if (!EncryptDecryptStringRoundTrip(cryptoApi, password, passwordSize,
                                               utf8Text.c_str(), static_cast<int>(utf8Text.size()), decryptedUtf8))
            {
                vectorOk = false;
                break;
            }

            std::wstring decryptedWide;
            if (!ConvertUtf8ToWide(decryptedUtf8.c_str(), static_cast<int>(decryptedUtf8.size()), decryptedWide))
            {
                vectorOk = false;
                break;
            }

            outputWideStrings.push_back(decryptedWide);
        }

        const bool ok = vectorOk && outputWideStrings == inputWideStrings;
        std::cout << "RunVectorWideStringDataTest: vector<wstring> (" << inputWideStrings.size() << " elements) -> "
                  << (ok ? "OK" : "FAILED") << std::endl;

        if (!ok)
        {
            std::cout << "RunVectorWideStringDataTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunVectorWideStringDataTest: PASSED (" << inputWideStrings.size() << " wide strings)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryTest(void)
{
    try
    {
        int failures = 0;

        {
            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_MICROSOFT);
            if (!factory)
            {
                std::cout << "RunProviderFactoryTest: FAILED CreateProviderFactory(PROVIDER_MICROSOFT)" << std::endl;
                ++failures;
            }
            else
            {
                if (!RoundTripAeadViaFactory("RunProviderFactoryTest", *factory, AEAD_AES_256_GCM, "Microsoft", "AES-256-GCM", true)) ++failures;
                if (!RoundTripLegacyViaFactory("RunProviderFactoryTest", *factory, LEGACY_AES_256_CBC, "Microsoft", "AES-256-CBC", true)) ++failures;
                if (!RoundTripAeadViaFactory("RunProviderFactoryTest", *factory, AEAD_TWOFISH_GCM, "Microsoft", "Twofish-GCM", false)) ++failures;
                if (!RoundTripLegacyViaFactory("RunProviderFactoryTest", *factory, LEGACY_AES_256_CTR, "Microsoft", "AES-256-CTR", false)) ++failures;
            }
        }

        {
            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_CRYPTOPP);
            if (!factory)
            {
                std::cout << "RunProviderFactoryTest: FAILED CreateProviderFactory(PROVIDER_CRYPTOPP)" << std::endl;
                ++failures;
            }
            else
            {
                if (!RoundTripAeadViaFactory("RunProviderFactoryTest", *factory, AEAD_AES_256_GCM, "CryptoPP", "AES-256-GCM", true)) ++failures;
                if (!RoundTripLegacyViaFactory("RunProviderFactoryTest", *factory, LEGACY_AES_256_CBC, "CryptoPP", "AES-256-CBC", true)) ++failures;
                if (!RoundTripAeadViaFactory("RunProviderFactoryTest", *factory, AEAD_AES_128_SIV, "CryptoPP", "AES-128-SIV", false)) ++failures;
                if (!RoundTripLegacyViaFactory("RunProviderFactoryTest", *factory, LEGACY_AES_256_CTR, "CryptoPP", "AES-256-CTR", true)) ++failures;
            }
        }

        {
            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_BOTAN);
            if (!factory)
            {
                std::cout << "RunProviderFactoryTest: FAILED CreateProviderFactory(PROVIDER_BOTAN)" << std::endl;
                ++failures;
            }
            else
            {
                if (!RoundTripAeadViaFactory("RunProviderFactoryTest", *factory, AEAD_AES_256_GCM, "Botan", "AES-256-GCM", true)) ++failures;
                if (!RoundTripLegacyViaFactory("RunProviderFactoryTest", *factory, LEGACY_AES_256_CBC, "Botan", "AES-256-CBC", true)) ++failures;
                if (!RoundTripAeadViaFactory("RunProviderFactoryTest", *factory, AEAD_AES_128_SIV, "Botan", "AES-128-SIV", true)) ++failures;
                if (!RoundTripLegacyViaFactory("RunProviderFactoryTest", *factory, LEGACY_AES_256_ECB, "Botan", "AES-256-ECB", false)) ++failures;
            }
        }

        {
            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_OPENSSL);
            if (!factory)
            {
                std::cout << "RunProviderFactoryTest: FAILED CreateProviderFactory(PROVIDER_OPENSSL)" << std::endl;
                ++failures;
            }
            else
            {
                if (!RoundTripAeadViaFactory("RunProviderFactoryTest", *factory, AEAD_AES_256_GCM, "OpenSSL", "AES-256-GCM", true)) ++failures;
                if (!RoundTripLegacyViaFactory("RunProviderFactoryTest", *factory, LEGACY_AES_256_CBC, "OpenSSL", "AES-256-CBC", true)) ++failures;
                if (!RoundTripAeadViaFactory("RunProviderFactoryTest", *factory, AEAD_AES_128_EAX, "OpenSSL", "AES-128-EAX", false)) ++failures;
                if (!RoundTripLegacyViaFactory("RunProviderFactoryTest", *factory, LEGACY_AES_256_ECB, "OpenSSL", "AES-256-ECB", true)) ++failures;
            }
        }

        if (failures != 0)
        {
            std::cout << "RunProviderFactoryTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunProviderFactoryTest: PASSED (Microsoft, CryptoPP, Botan, OpenSSL)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryFileTest(void)
{
    try
    {
        struct ProviderCase
        {
            ProviderKind kind;
            const char* name;
        };

        const ProviderCase providerCases[] =
        {
            { PROVIDER_MICROSOFT, "Microsoft" },
            { PROVIDER_CRYPTOPP,  "CryptoPP" },
            { PROVIDER_BOTAN,     "Botan" },
            { PROVIDER_OPENSSL,   "OpenSSL" }
        };

        const char* inputFilePath = "cryptoapi_factory_filetest_in.bin";
        const char* encryptedFilePath = "cryptoapi_factory_filetest_enc.bin";
        const char* decryptedFilePath = "cryptoapi_factory_filetest_out.bin";

        std::vector<unsigned char> inputData(2 * 1048576 + 777);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        int failures = 0;

        for (std::size_t caseIndex = 0; caseIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++caseIndex)
        {
            const ProviderKind kind = providerCases[caseIndex].kind;
            const char* name = providerCases[caseIndex].name;

            if (!WriteTesterFile(inputFilePath, inputData))
            {
                std::cout << "RunProviderFactoryFileTest: FAILED [" << name << "] write input file" << std::endl;
                ++failures;
                continue;
            }

            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
            std::unique_ptr<IAeadCipher> encryptCipher = factory ? factory->CreateAeadCipher(AEAD_AES_256_GCM) : nullptr;
            std::unique_ptr<IRandomSource> randomSource = factory ? factory->CreateRandomSource() : nullptr;
            if (!encryptCipher || !randomSource)
            {
                std::cout << "RunProviderFactoryFileTest: FAILED [" << name << "] CreateProviderFactory/CreateAeadCipher/CreateRandomSource" << std::endl;
                std::remove(inputFilePath);
                ++failures;
                continue;
            }

            const unsigned int keySize = encryptCipher->GetKeySize();
            const unsigned int chunkSize = 512u * 1024u; // deliberately smaller than inputData.size() so PrintFileProgress fires more than once

            std::vector<unsigned char> key(keySize);
            for (unsigned int index = 0; index < keySize; ++index) key[index] = static_cast<unsigned char>(index * 13 + 7);

            if (!encryptCipher->SetKey(key.data(), keySize))
            {
                std::cout << "RunProviderFactoryFileTest: FAILED [" << name << "] SetKey (encrypt)" << std::endl;
                std::remove(inputFilePath);
                ++failures;
                continue;
            }

            unsigned int requiredEncryptSize = 0;
            encryptCipher->EncryptChunked(*randomSource, &inputData[0], static_cast<unsigned int>(inputData.size()), chunkSize,
                                          nullptr, 0, &requiredEncryptSize, nullptr, nullptr);

            std::vector<unsigned char> encryptedFileData(requiredEncryptSize);
            unsigned int encryptedSize = 0;
            if (!encryptCipher->EncryptChunked(*randomSource, &inputData[0], static_cast<unsigned int>(inputData.size()), chunkSize,
                                               encryptedFileData.data(), requiredEncryptSize, &encryptedSize,
                                               &PrintFileProgress, nullptr) ||
                !WriteTesterFile(encryptedFilePath, encryptedFileData))
            {
                std::cout << "RunProviderFactoryFileTest: FAILED [" << name << "] EncryptChunked/write encrypted file" << std::endl;
                std::remove(inputFilePath);
                ++failures;
                continue;
            }

            std::cout << std::endl;

            // Decrypt side: a fresh cipher instance from the same factory/algorithm, exactly as a
            // separate decrypt run (e.g. a different process later) would do it. The record stream
            // is self-delimited, so DecryptChunked needs no chunkSize argument.
            std::unique_ptr<IAeadCipher> decryptCipher = factory->CreateAeadCipher(AEAD_AES_256_GCM);
            std::vector<unsigned char> encryptedFileReadBack;
            if (!decryptCipher || !decryptCipher->SetKey(key.data(), keySize) ||
                !ReadTesterFile(encryptedFilePath, encryptedFileReadBack))
            {
                std::cout << "RunProviderFactoryFileTest: FAILED [" << name << "] read encrypted file / SetKey" << std::endl;
                std::remove(inputFilePath);
                std::remove(encryptedFilePath);
                ++failures;
                continue;
            }

            unsigned int requiredDecryptSize = 0;
            decryptCipher->DecryptChunked(&encryptedFileReadBack[0], static_cast<unsigned int>(encryptedFileReadBack.size()),
                                          nullptr, 0, &requiredDecryptSize, nullptr, nullptr);

            std::vector<unsigned char> decryptedData(requiredDecryptSize);
            unsigned int decryptedSize = 0;
            if (!decryptCipher->DecryptChunked(&encryptedFileReadBack[0], static_cast<unsigned int>(encryptedFileReadBack.size()),
                                               decryptedData.data(), requiredDecryptSize, &decryptedSize,
                                               &PrintFileProgress, nullptr) ||
                !WriteTesterFile(decryptedFilePath, decryptedData))
            {
                std::cout << "RunProviderFactoryFileTest: FAILED [" << name << "] DecryptChunked/tag verify" << std::endl;
                std::remove(inputFilePath);
                std::remove(encryptedFilePath);
                ++failures;
                continue;
            }

            std::cout << std::endl;

            std::vector<unsigned char> outputData;
            const bool readOk = ReadTesterFile(decryptedFilePath, outputData);

            std::remove(inputFilePath);
            std::remove(encryptedFilePath);
            std::remove(decryptedFilePath);

            if (!readOk || outputData.size() != inputData.size() ||
                std::memcmp(&outputData[0], &inputData[0], inputData.size()) != 0)
            {
                std::cout << "RunProviderFactoryFileTest: FAILED [" << name << "] content mismatch" << std::endl;
                ++failures;
                continue;
            }

            std::cout << "RunProviderFactoryFileTest: PASSED [" << name << "/AES-256-GCM] ("
                      << inputData.size() << " bytes)" << std::endl;
        }

        if (failures != 0)
        {
            std::cout << "RunProviderFactoryFileTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunProviderFactoryFileTest: PASSED (Microsoft, CryptoPP, Botan, OpenSSL)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryStringTest(void)
{
    try
    {
        std::vector<char> inputText(2 * 1048576 + 321);
        for (std::size_t index = 0; index < inputText.size(); ++index)
        {
            inputText[index] = static_cast<char>('A' + (index % 26));
        }

        return RunProviderFactoryInMemoryRoundTrip("RunProviderFactoryStringTest",
                                                   reinterpret_cast<const unsigned char*>(&inputText[0]),
                                                   inputText.size());
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryBufferTest(void)
{
    try
    {
        std::vector<unsigned char> inputBuffer(2 * 1048576 + 555);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        return RunProviderFactoryInMemoryRoundTrip("RunProviderFactoryBufferTest", &inputBuffer[0], inputBuffer.size());
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryBytesTest(void)
{
    try
    {
        std::vector<unsigned char> inputBuffer(2 * 1048576 + 999);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        return RunProviderFactoryInMemoryRoundTrip("RunProviderFactoryBytesTest", &inputBuffer[0], inputBuffer.size());
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryHashTest(void)
{
    try
    {
        int failures = 0;

        {
            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_MICROSOFT);
            if (!factory)
            {
                std::cout << "RunProviderFactoryHashTest: FAILED CreateProviderFactory(PROVIDER_MICROSOFT)" << std::endl;
                ++failures;
            }
            else
            {
                if (!RoundTripHashViaFactory("RunProviderFactoryHashTest", *factory, HASH_SHA256, "Microsoft", "SHA256", true)) ++failures;
                if (!RoundTripHashViaFactory("RunProviderFactoryHashTest", *factory, HASH_RIPEMD160, "Microsoft", "RIPEMD160", false)) ++failures;
            }
        }

        {
            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_CRYPTOPP);
            if (!factory)
            {
                std::cout << "RunProviderFactoryHashTest: FAILED CreateProviderFactory(PROVIDER_CRYPTOPP)" << std::endl;
                ++failures;
            }
            else
            {
                if (!RoundTripHashViaFactory("RunProviderFactoryHashTest", *factory, HASH_SHA256, "CryptoPP", "SHA256", true)) ++failures;
                if (!RoundTripHashViaFactory("RunProviderFactoryHashTest", *factory, HASH_BLAKE2B, "CryptoPP", "BLAKE2B", true)) ++failures;
            }
        }

        {
            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_BOTAN);
            if (!factory)
            {
                std::cout << "RunProviderFactoryHashTest: FAILED CreateProviderFactory(PROVIDER_BOTAN)" << std::endl;
                ++failures;
            }
            else
            {
                if (!RoundTripHashViaFactory("RunProviderFactoryHashTest", *factory, HASH_SHA256, "Botan", "SHA256", true)) ++failures;
                if (!RoundTripHashViaFactory("RunProviderFactoryHashTest", *factory, HASH_SHA512_256, "Botan", "SHA512_256", true)) ++failures;
            }
        }

        {
            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_OPENSSL);
            if (!factory)
            {
                std::cout << "RunProviderFactoryHashTest: FAILED CreateProviderFactory(PROVIDER_OPENSSL)" << std::endl;
                ++failures;
            }
            else
            {
                if (!RoundTripHashViaFactory("RunProviderFactoryHashTest", *factory, HASH_SHA256, "OpenSSL", "SHA256", true)) ++failures;
                if (!RoundTripHashViaFactory("RunProviderFactoryHashTest", *factory, HASH_SHA3_512, "OpenSSL", "SHA3_512", true)) ++failures;
            }
        }

        if (failures != 0)
        {
            std::cout << "RunProviderFactoryHashTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunProviderFactoryHashTest: PASSED (Microsoft, CryptoPP, Botan, OpenSSL)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryHashFileTest(void)
{
    try
    {
        struct ProviderCase
        {
            ProviderKind kind;
            const char* name;
        };

        const ProviderCase providerCases[] =
        {
            { PROVIDER_MICROSOFT, "Microsoft" },
            { PROVIDER_CRYPTOPP,  "CryptoPP" },
            { PROVIDER_BOTAN,     "Botan" },
            { PROVIDER_OPENSSL,   "OpenSSL" }
        };

        const char* inputFilePath = "cryptoapi_factory_hashfiletest_in.bin";

        std::vector<unsigned char> inputData(2 * 1048576 + 777);
        for (std::size_t index = 0; index < inputData.size(); ++index)
        {
            inputData[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        int failures = 0;

        for (std::size_t caseIndex = 0; caseIndex < sizeof(providerCases) / sizeof(providerCases[0]); ++caseIndex)
        {
            const ProviderKind kind = providerCases[caseIndex].kind;
            const char* name = providerCases[caseIndex].name;

            if (!WriteTesterFile(inputFilePath, inputData))
            {
                std::cout << "RunProviderFactoryHashFileTest: FAILED [" << name << "] write input file" << std::endl;
                ++failures;
                continue;
            }

            std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(kind);
            std::unique_ptr<IHashService> firstHashService = factory ? factory->CreateHashService(HASH_SHA256) : nullptr;
            if (!firstHashService)
            {
                std::cout << "RunProviderFactoryHashFileTest: FAILED [" << name << "] CreateProviderFactory/CreateHashService" << std::endl;
                std::remove(inputFilePath);
                ++failures;
                continue;
            }

            std::vector<unsigned char> readBackData;
            if (!ReadTesterFile(inputFilePath, readBackData))
            {
                std::cout << "RunProviderFactoryHashFileTest: FAILED [" << name << "] read input file" << std::endl;
                std::remove(inputFilePath);
                ++failures;
                continue;
            }

            const unsigned int hashSize = firstHashService->GetHashSize();
            std::vector<unsigned char> firstDigest(hashSize);
            if (!firstHashService->ComputeHash(&readBackData[0], static_cast<unsigned int>(readBackData.size()), firstDigest.data(), hashSize))
            {
                std::cout << "RunProviderFactoryHashFileTest: FAILED [" << name << "] ComputeHash (first instance)" << std::endl;
                std::remove(inputFilePath);
                ++failures;
                continue;
            }

            // A second, independent IHashService instance from the same factory -- like a
            // different process re-hashing the same file later -- must agree exactly.
            std::unique_ptr<IHashService> secondHashService = factory->CreateHashService(HASH_SHA256);
            std::vector<unsigned char> secondDigest(hashSize);
            if (!secondHashService || !secondHashService->ComputeHash(&readBackData[0], static_cast<unsigned int>(readBackData.size()), secondDigest.data(), hashSize) ||
                secondDigest != firstDigest)
            {
                std::cout << "RunProviderFactoryHashFileTest: FAILED [" << name << "] second-instance mismatch" << std::endl;
                std::remove(inputFilePath);
                ++failures;
                continue;
            }

            // Cross-check against CCryptoApi::ComputeHashFile (Hash-only 2-argument constructor)
            // reading the same file from disk end to end.
            CCryptoApi cryptoApi(kind, HASH_SHA256);
            std::vector<unsigned char> apiDigest(hashSize);
            int apiDigestSize = 0;
            const int status = cryptoApi.ComputeHashFile(inputFilePath, static_cast<int>(hashSize), apiDigest.data(), &apiDigestSize, nullptr, nullptr);

            std::remove(inputFilePath);

            if (status != NO_ERROR || apiDigestSize != static_cast<int>(hashSize) ||
                std::memcmp(apiDigest.data(), firstDigest.data(), hashSize) != 0)
            {
                std::cout << "RunProviderFactoryHashFileTest: FAILED [" << name << "] CCryptoApi::ComputeHashFile mismatch status=" << status << std::endl;
                ++failures;
                continue;
            }

            std::cout << "RunProviderFactoryHashFileTest: PASSED [" << name << "/SHA256] (" << inputData.size() << " bytes)" << std::endl;
        }

        if (failures != 0)
        {
            std::cout << "RunProviderFactoryHashFileTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunProviderFactoryHashFileTest: PASSED (Microsoft, CryptoPP, Botan, OpenSSL)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryHashStringTest(void)
{
    try
    {
        std::vector<char> inputText(2 * 1048576 + 321);
        for (std::size_t index = 0; index < inputText.size(); ++index)
        {
            inputText[index] = static_cast<char>('A' + (index % 26));
        }

        return HashViaFactoryInMemory("RunProviderFactoryHashStringTest",
                                      reinterpret_cast<const unsigned char*>(&inputText[0]), inputText.size());
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryHashBufferTest(void)
{
    try
    {
        std::vector<unsigned char> inputBuffer(2 * 1048576 + 555);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        return HashViaFactoryInMemory("RunProviderFactoryHashBufferTest", &inputBuffer[0], inputBuffer.size());
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunProviderFactoryHashBytesTest(void)
{
    try
    {
        std::vector<unsigned char> inputBuffer(2 * 1048576 + 999);
        for (std::size_t index = 0; index < inputBuffer.size(); ++index)
        {
            inputBuffer[index] = static_cast<unsigned char>(index * 2654435761u >> 24);
        }

        return HashViaFactoryInMemory("RunProviderFactoryHashBytesTest", &inputBuffer[0], inputBuffer.size());
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunMicrosoftProviderAllAlgorithmsTest(void)
{
    try
    {
        std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_MICROSOFT);
        if (!factory)
        {
            std::cout << "RunMicrosoftProviderAllAlgorithmsTest: FAILED CreateProviderFactory(PROVIDER_MICROSOFT)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        const AeadAlgorithm aeadAlgorithms[] =
        {
            AEAD_AES_128_GCM, AEAD_AES_192_GCM, AEAD_AES_256_GCM,
            AEAD_AES_128_CCM, AEAD_AES_192_CCM, AEAD_AES_256_CCM,
            AEAD_AES_128_EAX, AEAD_AES_192_EAX, AEAD_AES_256_EAX,
            AEAD_AES_128_SIV, AEAD_AES_256_SIV,
            AEAD_AES_128_GCM_SIV, AEAD_AES_256_GCM_SIV,
            AEAD_CHACHA20_POLY1305, AEAD_TWOFISH_GCM, AEAD_SERPENT_GCM, AEAD_CAMELLIA_GCM
        };

        const LegacySymmetricAlgorithm legacyAlgorithms[] =
        {
            LEGACY_AES_128_CBC, LEGACY_AES_192_CBC, LEGACY_AES_256_CBC,
            LEGACY_AES_128_CTR, LEGACY_AES_192_CTR, LEGACY_AES_256_CTR,
            LEGACY_AES_128_CFB, LEGACY_AES_192_CFB, LEGACY_AES_256_CFB,
            LEGACY_AES_128_OFB, LEGACY_AES_192_OFB, LEGACY_AES_256_OFB,
            LEGACY_AES_128_ECB, LEGACY_AES_192_ECB, LEGACY_AES_256_ECB,
            LEGACY_RC2_CBC, LEGACY_RC2_ECB,
            LEGACY_DES_CBC, LEGACY_DES_ECB,
            LEGACY_3DES_CBC, LEGACY_3DES_ECB,
            LEGACY_RC4
        };

        const AsymmetricAlgorithm asymmetricAlgorithms[] =
        {
            ASYMMETRIC_RSA_1024, ASYMMETRIC_RSA_2048, ASYMMETRIC_RSA_3072, ASYMMETRIC_RSA_4096
        };

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t index = 0; index < sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]); ++index)
        {
            const AeadAlgorithm algorithm = aeadAlgorithms[index];
            const bool supported = factory->SupportsAeadAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripAeadViaFactory("RunMicrosoftProviderAllAlgorithmsTest", *factory, algorithm, "Microsoft", AeadAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        for (std::size_t index = 0; index < sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]); ++index)
        {
            const LegacySymmetricAlgorithm algorithm = legacyAlgorithms[index];
            const bool supported = factory->SupportsLegacyAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripLegacyViaFactory("RunMicrosoftProviderAllAlgorithmsTest", *factory, algorithm, "Microsoft", LegacyAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        for (std::size_t index = 0; index < sizeof(asymmetricAlgorithms) / sizeof(asymmetricAlgorithms[0]); ++index)
        {
            const AsymmetricAlgorithm algorithm = asymmetricAlgorithms[index];
            const bool supported = factory->SupportsAsymmetricAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripAsymmetricViaFactory("RunMicrosoftProviderAllAlgorithmsTest", *factory, algorithm, "Microsoft", AsymmetricAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        const std::size_t totalCount = sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]) +
                                       sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]) +
                                       sizeof(asymmetricAlgorithms) / sizeof(asymmetricAlgorithms[0]);

        if (failures != 0)
        {
            std::cout << "RunMicrosoftProviderAllAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunMicrosoftProviderAllAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and round-tripped, "
                  << (totalCount - static_cast<std::size_t>(supportedCount))
                  << " correctly rejected)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunCryptoPPProviderAllAlgorithmsTest(void)
{
    try
    {
        std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_CRYPTOPP);
        if (!factory)
        {
            std::cout << "RunCryptoPPProviderAllAlgorithmsTest: FAILED CreateProviderFactory(PROVIDER_CRYPTOPP)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        const AeadAlgorithm aeadAlgorithms[] =
        {
            AEAD_AES_128_GCM, AEAD_AES_192_GCM, AEAD_AES_256_GCM,
            AEAD_AES_128_CCM, AEAD_AES_192_CCM, AEAD_AES_256_CCM,
            AEAD_AES_128_EAX, AEAD_AES_192_EAX, AEAD_AES_256_EAX,
            AEAD_AES_128_SIV, AEAD_AES_256_SIV,
            AEAD_AES_128_GCM_SIV, AEAD_AES_256_GCM_SIV,
            AEAD_CHACHA20_POLY1305, AEAD_TWOFISH_GCM, AEAD_SERPENT_GCM, AEAD_CAMELLIA_GCM
        };

        const LegacySymmetricAlgorithm legacyAlgorithms[] =
        {
            LEGACY_AES_128_CBC, LEGACY_AES_192_CBC, LEGACY_AES_256_CBC,
            LEGACY_AES_128_CTR, LEGACY_AES_192_CTR, LEGACY_AES_256_CTR,
            LEGACY_AES_128_CFB, LEGACY_AES_192_CFB, LEGACY_AES_256_CFB,
            LEGACY_AES_128_OFB, LEGACY_AES_192_OFB, LEGACY_AES_256_OFB,
            LEGACY_AES_128_ECB, LEGACY_AES_192_ECB, LEGACY_AES_256_ECB,
            LEGACY_RC2_CBC, LEGACY_RC2_ECB,
            LEGACY_DES_CBC, LEGACY_DES_ECB,
            LEGACY_3DES_CBC, LEGACY_3DES_ECB,
            LEGACY_RC4
        };

        const AsymmetricAlgorithm asymmetricAlgorithms[] =
        {
            ASYMMETRIC_RSA_1024, ASYMMETRIC_RSA_2048, ASYMMETRIC_RSA_3072, ASYMMETRIC_RSA_4096
        };

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t index = 0; index < sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]); ++index)
        {
            const AeadAlgorithm algorithm = aeadAlgorithms[index];
            const bool supported = factory->SupportsAeadAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripAeadViaFactory("RunCryptoPPProviderAllAlgorithmsTest", *factory, algorithm, "CryptoPP", AeadAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        for (std::size_t index = 0; index < sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]); ++index)
        {
            const LegacySymmetricAlgorithm algorithm = legacyAlgorithms[index];
            const bool supported = factory->SupportsLegacyAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripLegacyViaFactory("RunCryptoPPProviderAllAlgorithmsTest", *factory, algorithm, "CryptoPP", LegacyAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        for (std::size_t index = 0; index < sizeof(asymmetricAlgorithms) / sizeof(asymmetricAlgorithms[0]); ++index)
        {
            const AsymmetricAlgorithm algorithm = asymmetricAlgorithms[index];
            const bool supported = factory->SupportsAsymmetricAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripAsymmetricViaFactory("RunCryptoPPProviderAllAlgorithmsTest", *factory, algorithm, "CryptoPP", AsymmetricAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        const std::size_t totalCount = sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]) +
                                       sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]) +
                                       sizeof(asymmetricAlgorithms) / sizeof(asymmetricAlgorithms[0]);

        if (failures != 0)
        {
            std::cout << "RunCryptoPPProviderAllAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunCryptoPPProviderAllAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and round-tripped, "
                  << (totalCount - static_cast<std::size_t>(supportedCount))
                  << " correctly rejected)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunBotanProviderAllAlgorithmsTest(void)
{
    try
    {
        std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_BOTAN);
        if (!factory)
        {
            std::cout << "RunBotanProviderAllAlgorithmsTest: FAILED CreateProviderFactory(PROVIDER_BOTAN)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        const AeadAlgorithm aeadAlgorithms[] =
        {
            AEAD_AES_128_GCM, AEAD_AES_192_GCM, AEAD_AES_256_GCM,
            AEAD_AES_128_CCM, AEAD_AES_192_CCM, AEAD_AES_256_CCM,
            AEAD_AES_128_EAX, AEAD_AES_192_EAX, AEAD_AES_256_EAX,
            AEAD_AES_128_SIV, AEAD_AES_256_SIV,
            AEAD_AES_128_GCM_SIV, AEAD_AES_256_GCM_SIV,
            AEAD_CHACHA20_POLY1305, AEAD_TWOFISH_GCM, AEAD_SERPENT_GCM, AEAD_CAMELLIA_GCM
        };

        const LegacySymmetricAlgorithm legacyAlgorithms[] =
        {
            LEGACY_AES_128_CBC, LEGACY_AES_192_CBC, LEGACY_AES_256_CBC,
            LEGACY_AES_128_CTR, LEGACY_AES_192_CTR, LEGACY_AES_256_CTR,
            LEGACY_AES_128_CFB, LEGACY_AES_192_CFB, LEGACY_AES_256_CFB,
            LEGACY_AES_128_OFB, LEGACY_AES_192_OFB, LEGACY_AES_256_OFB,
            LEGACY_AES_128_ECB, LEGACY_AES_192_ECB, LEGACY_AES_256_ECB,
            LEGACY_RC2_CBC, LEGACY_RC2_ECB,
            LEGACY_DES_CBC, LEGACY_DES_ECB,
            LEGACY_3DES_CBC, LEGACY_3DES_ECB,
            LEGACY_RC4
        };

        const AsymmetricAlgorithm asymmetricAlgorithms[] =
        {
            ASYMMETRIC_RSA_1024, ASYMMETRIC_RSA_2048, ASYMMETRIC_RSA_3072, ASYMMETRIC_RSA_4096
        };

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t index = 0; index < sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]); ++index)
        {
            const AeadAlgorithm algorithm = aeadAlgorithms[index];
            const bool supported = factory->SupportsAeadAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripAeadViaFactory("RunBotanProviderAllAlgorithmsTest", *factory, algorithm, "Botan", AeadAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        for (std::size_t index = 0; index < sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]); ++index)
        {
            const LegacySymmetricAlgorithm algorithm = legacyAlgorithms[index];
            const bool supported = factory->SupportsLegacyAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripLegacyViaFactory("RunBotanProviderAllAlgorithmsTest", *factory, algorithm, "Botan", LegacyAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        for (std::size_t index = 0; index < sizeof(asymmetricAlgorithms) / sizeof(asymmetricAlgorithms[0]); ++index)
        {
            const AsymmetricAlgorithm algorithm = asymmetricAlgorithms[index];
            const bool supported = factory->SupportsAsymmetricAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripAsymmetricViaFactory("RunBotanProviderAllAlgorithmsTest", *factory, algorithm, "Botan", AsymmetricAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        const std::size_t totalCount = sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]) +
                                       sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]) +
                                       sizeof(asymmetricAlgorithms) / sizeof(asymmetricAlgorithms[0]);

        if (failures != 0)
        {
            std::cout << "RunBotanProviderAllAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunBotanProviderAllAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and round-tripped, "
                  << (totalCount - static_cast<std::size_t>(supportedCount))
                  << " correctly rejected)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunOpenSslProviderAllAlgorithmsTest(void)
{
    try
    {
        std::unique_ptr<ICryptoProviderFactory> factory = CreateProviderFactory(PROVIDER_OPENSSL);
        if (!factory)
        {
            std::cout << "RunOpenSslProviderAllAlgorithmsTest: FAILED CreateProviderFactory(PROVIDER_OPENSSL)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        const AeadAlgorithm aeadAlgorithms[] =
        {
            AEAD_AES_128_GCM, AEAD_AES_192_GCM, AEAD_AES_256_GCM,
            AEAD_AES_128_CCM, AEAD_AES_192_CCM, AEAD_AES_256_CCM,
            AEAD_AES_128_EAX, AEAD_AES_192_EAX, AEAD_AES_256_EAX,
            AEAD_AES_128_SIV, AEAD_AES_256_SIV,
            AEAD_AES_128_GCM_SIV, AEAD_AES_256_GCM_SIV,
            AEAD_CHACHA20_POLY1305, AEAD_TWOFISH_GCM, AEAD_SERPENT_GCM, AEAD_CAMELLIA_GCM
        };

        const LegacySymmetricAlgorithm legacyAlgorithms[] =
        {
            LEGACY_AES_128_CBC, LEGACY_AES_192_CBC, LEGACY_AES_256_CBC,
            LEGACY_AES_128_CTR, LEGACY_AES_192_CTR, LEGACY_AES_256_CTR,
            LEGACY_AES_128_CFB, LEGACY_AES_192_CFB, LEGACY_AES_256_CFB,
            LEGACY_AES_128_OFB, LEGACY_AES_192_OFB, LEGACY_AES_256_OFB,
            LEGACY_AES_128_ECB, LEGACY_AES_192_ECB, LEGACY_AES_256_ECB,
            LEGACY_RC2_CBC, LEGACY_RC2_ECB,
            LEGACY_DES_CBC, LEGACY_DES_ECB,
            LEGACY_3DES_CBC, LEGACY_3DES_ECB,
            LEGACY_RC4
        };

        const AsymmetricAlgorithm asymmetricAlgorithms[] =
        {
            ASYMMETRIC_RSA_1024, ASYMMETRIC_RSA_2048, ASYMMETRIC_RSA_3072, ASYMMETRIC_RSA_4096
        };

        int failures = 0;
        int supportedCount = 0;

        for (std::size_t index = 0; index < sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]); ++index)
        {
            const AeadAlgorithm algorithm = aeadAlgorithms[index];
            const bool supported = factory->SupportsAeadAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripAeadViaFactory("RunOpenSslProviderAllAlgorithmsTest", *factory, algorithm, "OpenSSL", AeadAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        for (std::size_t index = 0; index < sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]); ++index)
        {
            const LegacySymmetricAlgorithm algorithm = legacyAlgorithms[index];
            const bool supported = factory->SupportsLegacyAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripLegacyViaFactory("RunOpenSslProviderAllAlgorithmsTest", *factory, algorithm, "OpenSSL", LegacyAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        for (std::size_t index = 0; index < sizeof(asymmetricAlgorithms) / sizeof(asymmetricAlgorithms[0]); ++index)
        {
            const AsymmetricAlgorithm algorithm = asymmetricAlgorithms[index];
            const bool supported = factory->SupportsAsymmetricAlgorithm(algorithm);
            if (supported)
            {
                ++supportedCount;
            }

            if (!RoundTripAsymmetricViaFactory("RunOpenSslProviderAllAlgorithmsTest", *factory, algorithm, "OpenSSL", AsymmetricAlgorithmName(algorithm), supported))
            {
                ++failures;
            }
        }

        const std::size_t totalCount = sizeof(aeadAlgorithms) / sizeof(aeadAlgorithms[0]) +
                                       sizeof(legacyAlgorithms) / sizeof(legacyAlgorithms[0]) +
                                       sizeof(asymmetricAlgorithms) / sizeof(asymmetricAlgorithms[0]);

        if (failures != 0)
        {
            std::cout << "RunOpenSslProviderAllAlgorithmsTest: " << failures << " FAILURE(S)" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunOpenSslProviderAllAlgorithmsTest: PASSED (" << supportedCount << " algorithms actually supported and round-tripped, "
                  << (totalCount - static_cast<std::size_t>(supportedCount))
                  << " correctly rejected)" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::runNonBlocking(const char* testName, int (CCryptoApiTester::*testMethod)(void))
{
    try
    {
        std::future<int> asyncResult = std::async(std::launch::async, testMethod, this);

        std::cout << testName << "NonBlocking: dispatched to a background thread; main thread stays free" << std::endl;

        int waitCount = 0;
        while (asyncResult.wait_for(std::chrono::milliseconds(250)) != std::future_status::ready)
        {
            std::cout << testName << "NonBlocking: main thread still doing other work (" << ++waitCount << ")" << std::endl;
        }

        const int result = asyncResult.get();
        std::cout << testName << "NonBlocking: background test finished with status=" << result << std::endl;
        return result;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptDecryptFileTestNonBlocking(void)
{
    return runNonBlocking("RunEncryptDecryptFileTest", &CCryptoApiTester::RunEncryptDecryptFileTest);
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptDecryptStringTestNonBlocking(void)
{
    return runNonBlocking("RunEncryptDecryptStringTest", &CCryptoApiTester::RunEncryptDecryptStringTest);
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptDecryptBufferTestNonBlocking(void)
{
    return runNonBlocking("RunEncryptDecryptBufferTest", &CCryptoApiTester::RunEncryptDecryptBufferTest);
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunEncryptDecryptBytesTestNonBlocking(void)
{
    return runNonBlocking("RunEncryptDecryptBytesTest", &CCryptoApiTester::RunEncryptDecryptBytesTest);
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashFileTestNonBlocking(void)
{
    return runNonBlocking("RunHashFileTest", &CCryptoApiTester::RunHashFileTest);
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashStringTestNonBlocking(void)
{
    return runNonBlocking("RunHashStringTest", &CCryptoApiTester::RunHashStringTest);
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashBufferTestNonBlocking(void)
{
    return runNonBlocking("RunHashBufferTest", &CCryptoApiTester::RunHashBufferTest);
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunHashBytesTestNonBlocking(void)
{
    return runNonBlocking("RunHashBytesTest", &CCryptoApiTester::RunHashBytesTest);
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPgpKeyGenerationTest(void)
{
    try
    {
        CPgpEngine pgp;
        const char* userId = "Alice <alice@example.com>";
        const char* password = "correct horse battery staple";

        int status = pgp.GenerateKeyPair(userId, static_cast<int>(std::strlen(userId)), password, static_cast<int>(std::strlen(password)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpKeyGenerationTest: FAILED GenerateKeyPair status=" << status << std::endl;
            return status;
        }

        char keyId[17];
        status = pgp.GetKeyId(keyId, 17);
        if (status != NO_ERROR || std::strlen(keyId) != 16)
        {
            std::cout << "RunPgpKeyGenerationTest: FAILED GetKeyId status=" << status << " keyId=" << keyId << std::endl;
            return UNEXPECTED_ERROR;
        }

        int requiredSize = 0;
        status = pgp.ExportPublicKeyArmored(0, nullptr, &requiredSize);
        if (status != BUFFER_TOO_SMALL || requiredSize <= 0)
        {
            std::cout << "RunPgpKeyGenerationTest: FAILED ExportPublicKeyArmored capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<char> publicKeyArmored(static_cast<std::size_t>(requiredSize));
        int actualPublicKeySize = 0;
        status = pgp.ExportPublicKeyArmored(requiredSize, &publicKeyArmored[0], &actualPublicKeySize);
        if (status != NO_ERROR || actualPublicKeySize != requiredSize)
        {
            std::cout << "RunPgpKeyGenerationTest: FAILED ExportPublicKeyArmored status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        const std::string publicKeyText(publicKeyArmored.begin(), publicKeyArmored.end());
        if (publicKeyText.find("-----BEGIN PGP PUBLIC KEY BLOCK-----") == std::string::npos ||
            publicKeyText.find("-----END PGP PUBLIC KEY BLOCK-----") == std::string::npos)
        {
            std::cout << "RunPgpKeyGenerationTest: FAILED public key armor framing missing" << std::endl;
            return UNEXPECTED_ERROR;
        }

        requiredSize = 0;
        status = pgp.ExportSecretKeyArmored(0, nullptr, &requiredSize);
        if (status != BUFFER_TOO_SMALL || requiredSize <= 0)
        {
            std::cout << "RunPgpKeyGenerationTest: FAILED ExportSecretKeyArmored capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<char> secretKeyArmored(static_cast<std::size_t>(requiredSize));
        int actualSecretKeySize = 0;
        status = pgp.ExportSecretKeyArmored(requiredSize, &secretKeyArmored[0], &actualSecretKeySize);
        if (status != NO_ERROR || actualSecretKeySize != requiredSize)
        {
            std::cout << "RunPgpKeyGenerationTest: FAILED ExportSecretKeyArmored status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        const std::string secretKeyText(secretKeyArmored.begin(), secretKeyArmored.end());
        if (secretKeyText.find("-----BEGIN PGP PRIVATE KEY BLOCK-----") == std::string::npos ||
            secretKeyText.find("-----END PGP PRIVATE KEY BLOCK-----") == std::string::npos)
        {
            std::cout << "RunPgpKeyGenerationTest: FAILED secret key armor framing missing" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunPgpKeyGenerationTest: PASSED keyId=" << keyId << " publicKeyArmoredSize=" << actualPublicKeySize
                  << " secretKeyArmoredSize=" << actualSecretKeySize << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPgpEncryptDecryptTest(void)
{
    try
    {
        CPgpEngine alice;
        CPgpEngine bob;
        const char* aliceUserId = "Alice <alice@example.com>";
        const char* bobUserId = "Bob <bob@example.com>";
        const char* alicePassword = "alice-password-1";
        const char* bobPassword = "bob-password-1";

        int status = alice.GenerateKeyPair(aliceUserId, static_cast<int>(std::strlen(aliceUserId)), alicePassword, static_cast<int>(std::strlen(alicePassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED alice GenerateKeyPair status=" << status << std::endl;
            return status;
        }
        status = bob.GenerateKeyPair(bobUserId, static_cast<int>(std::strlen(bobUserId)), bobPassword, static_cast<int>(std::strlen(bobPassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED bob GenerateKeyPair status=" << status << std::endl;
            return status;
        }

        int aliceKeySize = 0;
        alice.ExportPublicKeyArmored(0, nullptr, &aliceKeySize);
        std::vector<char> alicePublicKey(static_cast<std::size_t>(aliceKeySize));
        int aliceActualKeySize = 0;
        alice.ExportPublicKeyArmored(aliceKeySize, &alicePublicKey[0], &aliceActualKeySize);

        int bobKeySize = 0;
        bob.ExportPublicKeyArmored(0, nullptr, &bobKeySize);
        std::vector<char> bobPublicKey(static_cast<std::size_t>(bobKeySize));
        int bobActualKeySize = 0;
        bob.ExportPublicKeyArmored(bobKeySize, &bobPublicKey[0], &bobActualKeySize);

        status = bob.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(&alicePublicKey[0]), aliceActualKeySize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED bob ImportPeerPublicKey(alice) status=" << status << std::endl;
            return status;
        }
        status = alice.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(&bobPublicKey[0]), bobActualKeySize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED alice ImportPeerPublicKey(bob) status=" << status << std::endl;
            return status;
        }

        const std::vector<unsigned char> plaintext = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'B', 'o', 'b', '!', 0x00, 0x01, 0xFF };

        int cipherSize = 0;
        status = alice.EncryptBuffer(&plaintext[0], static_cast<int>(plaintext.size()), 0, nullptr, &cipherSize);
        if (status != BUFFER_TOO_SMALL || cipherSize <= 0)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED EncryptBuffer capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> ciphertext(static_cast<std::size_t>(cipherSize));
        int actualCipherSize = 0;
        status = alice.EncryptBuffer(&plaintext[0], static_cast<int>(plaintext.size()), cipherSize, &ciphertext[0], &actualCipherSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED EncryptBuffer status=" << status << std::endl;
            return status;
        }

        int plainSize = 0;
        status = bob.DecryptBuffer(bobPassword, static_cast<int>(std::strlen(bobPassword)), &ciphertext[0], actualCipherSize, 0, nullptr, &plainSize);
        if (status != BUFFER_TOO_SMALL || plainSize != static_cast<int>(plaintext.size()))
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED DecryptBuffer capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> decrypted(static_cast<std::size_t>(plainSize));
        int actualPlainSize = 0;
        status = bob.DecryptBuffer(bobPassword, static_cast<int>(std::strlen(bobPassword)), &ciphertext[0], actualCipherSize, plainSize, &decrypted[0], &actualPlainSize);
        if (status != NO_ERROR || decrypted != plaintext)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED DecryptBuffer status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        const char* textMessage = "Merhaba Bob, bu gizli bir mesaj.";
        int armoredSize = 0;
        status = bob.EncryptStringArmored(textMessage, static_cast<int>(std::strlen(textMessage)), 0, nullptr, &armoredSize);
        if (status != BUFFER_TOO_SMALL || armoredSize <= 0)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED EncryptStringArmored capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<char> armored(static_cast<std::size_t>(armoredSize));
        int actualArmoredSize = 0;
        status = bob.EncryptStringArmored(textMessage, static_cast<int>(std::strlen(textMessage)), armoredSize, &armored[0], &actualArmoredSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED EncryptStringArmored status=" << status << std::endl;
            return status;
        }

        int decodedSize = 0;
        status = alice.DecryptStringArmored(alicePassword, static_cast<int>(std::strlen(alicePassword)), &armored[0], actualArmoredSize, 0, nullptr, &decodedSize);
        if (status != BUFFER_TOO_SMALL || decodedSize != static_cast<int>(std::strlen(textMessage)))
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED DecryptStringArmored capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> decodedText(static_cast<std::size_t>(decodedSize));
        int actualDecodedSize = 0;
        status = alice.DecryptStringArmored(alicePassword, static_cast<int>(std::strlen(alicePassword)), &armored[0], actualArmoredSize, decodedSize, &decodedText[0], &actualDecodedSize);
        if (status != NO_ERROR || std::string(decodedText.begin(), decodedText.end()) != textMessage)
        {
            std::cout << "RunPgpEncryptDecryptTest: FAILED DecryptStringArmored status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunPgpEncryptDecryptTest: PASSED buffer(" << actualCipherSize << " bytes) and armored string(" << actualArmoredSize
                  << " bytes) round trips" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPgpSignVerifyTest(void)
{
    try
    {
        CPgpEngine alice;
        CPgpEngine bob;
        const char* aliceUserId = "Alice <alice@example.com>";
        const char* alicePassword = "alice-password-1";

        int status = alice.GenerateKeyPair(aliceUserId, static_cast<int>(std::strlen(aliceUserId)), alicePassword, static_cast<int>(std::strlen(alicePassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpSignVerifyTest: FAILED alice GenerateKeyPair status=" << status << std::endl;
            return status;
        }

        int aliceKeySize = 0;
        alice.ExportPublicKeyArmored(0, nullptr, &aliceKeySize);
        std::vector<char> alicePublicKey(static_cast<std::size_t>(aliceKeySize));
        int aliceActualKeySize = 0;
        alice.ExportPublicKeyArmored(aliceKeySize, &alicePublicKey[0], &aliceActualKeySize);

        status = bob.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(&alicePublicKey[0]), aliceActualKeySize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpSignVerifyTest: FAILED bob ImportPeerPublicKey status=" << status << std::endl;
            return status;
        }

        const std::vector<unsigned char> document = { 'C', 'o', 'n', 't', 'r', 'a', 'c', 't', ' ', 'v', '1' };

        int sigSize = 0;
        status = alice.SignBuffer(alicePassword, static_cast<int>(std::strlen(alicePassword)), &document[0], static_cast<int>(document.size()), 0, nullptr, &sigSize);
        if (status != BUFFER_TOO_SMALL || sigSize <= 0)
        {
            std::cout << "RunPgpSignVerifyTest: FAILED SignBuffer capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> signature(static_cast<std::size_t>(sigSize));
        int actualSigSize = 0;
        status = alice.SignBuffer(alicePassword, static_cast<int>(std::strlen(alicePassword)), &document[0], static_cast<int>(document.size()), sigSize, &signature[0], &actualSigSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpSignVerifyTest: FAILED SignBuffer status=" << status << std::endl;
            return status;
        }

        bool isValid = false;
        status = bob.VerifyBuffer(&document[0], static_cast<int>(document.size()), &signature[0], actualSigSize, &isValid);
        if (status != NO_ERROR || !isValid)
        {
            std::cout << "RunPgpSignVerifyTest: FAILED VerifyBuffer status=" << status << " isValid=" << isValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> tamperedSignature(signature.begin(), signature.begin() + actualSigSize);
        tamperedSignature[tamperedSignature.size() - 1] = static_cast<unsigned char>(tamperedSignature[tamperedSignature.size() - 1] ^ 0xFF);
        bool tamperedIsValid = true;
        status = bob.VerifyBuffer(&document[0], static_cast<int>(document.size()), &tamperedSignature[0], actualSigSize, &tamperedIsValid);
        if (status != NO_ERROR || tamperedIsValid)
        {
            std::cout << "RunPgpSignVerifyTest: FAILED tampered signature reported valid, status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunPgpSignVerifyTest: PASSED signature(" << actualSigSize << " bytes) verified, tampered signature correctly rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPgpClearSignTest(void)
{
    try
    {
        CPgpEngine alice;
        CPgpEngine bob;
        const char* aliceUserId = "Alice <alice@example.com>";
        const char* alicePassword = "alice-password-1";

        int status = alice.GenerateKeyPair(aliceUserId, static_cast<int>(std::strlen(aliceUserId)), alicePassword, static_cast<int>(std::strlen(alicePassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpClearSignTest: FAILED alice GenerateKeyPair status=" << status << std::endl;
            return status;
        }

        int aliceKeySize = 0;
        alice.ExportPublicKeyArmored(0, nullptr, &aliceKeySize);
        std::vector<char> alicePublicKey(static_cast<std::size_t>(aliceKeySize));
        int aliceActualKeySize = 0;
        alice.ExportPublicKeyArmored(aliceKeySize, &alicePublicKey[0], &aliceActualKeySize);

        status = bob.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(&alicePublicKey[0]), aliceActualKeySize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpClearSignTest: FAILED bob ImportPeerPublicKey status=" << status << std::endl;
            return status;
        }

        const char* message = "Line one.\nLine two.\n-Line starting with a dash.\nLine four.";

        int outSize = 0;
        status = alice.ClearSignString(alicePassword, static_cast<int>(std::strlen(alicePassword)), message, static_cast<int>(std::strlen(message)), 0, nullptr, &outSize);
        if (status != BUFFER_TOO_SMALL || outSize <= 0)
        {
            std::cout << "RunPgpClearSignTest: FAILED ClearSignString capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<char> clearSigned(static_cast<std::size_t>(outSize));
        int actualOutSize = 0;
        status = alice.ClearSignString(alicePassword, static_cast<int>(std::strlen(alicePassword)), message, static_cast<int>(std::strlen(message)), outSize, &clearSigned[0], &actualOutSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpClearSignTest: FAILED ClearSignString status=" << status << std::endl;
            return status;
        }

        bool isValid = false;
        status = bob.VerifyClearSignedString(&clearSigned[0], actualOutSize, &isValid);
        if (status != NO_ERROR || !isValid)
        {
            std::cout << "RunPgpClearSignTest: FAILED VerifyClearSignedString status=" << status << " isValid=" << isValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::string tampered(clearSigned.begin(), clearSigned.begin() + actualOutSize);
        const std::size_t tamperPos = tampered.find("Line two.");
        if (tamperPos == std::string::npos)
        {
            std::cout << "RunPgpClearSignTest: FAILED could not locate body text to tamper" << std::endl;
            return UNEXPECTED_ERROR;
        }
        tampered[tamperPos] = 'X';
        bool tamperedIsValid = true;
        status = bob.VerifyClearSignedString(tampered.c_str(), static_cast<int>(tampered.size()), &tamperedIsValid);
        if (status != NO_ERROR || tamperedIsValid)
        {
            std::cout << "RunPgpClearSignTest: FAILED tampered clear-signed text reported valid, status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunPgpClearSignTest: PASSED clear-sign(" << actualOutSize << " bytes) verified, tampered text correctly rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPgpArmorTest(void)
{
    try
    {
        CPgpEngine alice;
        CPgpEngine bob;
        const char* aliceUserId = "Alice <alice@example.com>";
        const char* alicePassword = "alice-password-1";

        int status = alice.GenerateKeyPair(aliceUserId, static_cast<int>(std::strlen(aliceUserId)), alicePassword, static_cast<int>(std::strlen(alicePassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpArmorTest: FAILED alice GenerateKeyPair status=" << status << std::endl;
            return status;
        }

        int aliceKeySize = 0;
        alice.ExportPublicKeyArmored(0, nullptr, &aliceKeySize);
        std::vector<char> alicePublicKey(static_cast<std::size_t>(aliceKeySize));
        int aliceActualKeySize = 0;
        alice.ExportPublicKeyArmored(aliceKeySize, &alicePublicKey[0], &aliceActualKeySize);

        status = bob.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(&alicePublicKey[0]), aliceActualKeySize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpArmorTest: FAILED bob ImportPeerPublicKey status=" << status << std::endl;
            return status;
        }

        const char* message = "Armor round-trip payload.";
        int armoredSize = 0;
        status = bob.EncryptStringArmored(message, static_cast<int>(std::strlen(message)), 0, nullptr, &armoredSize);
        if (status != BUFFER_TOO_SMALL || armoredSize <= 0)
        {
            std::cout << "RunPgpArmorTest: FAILED EncryptStringArmored capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<char> armored(static_cast<std::size_t>(armoredSize));
        int actualArmoredSize = 0;
        status = bob.EncryptStringArmored(message, static_cast<int>(std::strlen(message)), armoredSize, &armored[0], &actualArmoredSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpArmorTest: FAILED EncryptStringArmored status=" << status << std::endl;
            return status;
        }

        const std::string armoredText(armored.begin(), armored.begin() + actualArmoredSize);
        if (armoredText.find("-----BEGIN PGP MESSAGE-----") == std::string::npos ||
            armoredText.find("-----END PGP MESSAGE-----") == std::string::npos)
        {
            std::cout << "RunPgpArmorTest: FAILED armor framing missing" << std::endl;
            return UNEXPECTED_ERROR;
        }

        int decodedSize = 0;
        status = alice.DecryptStringArmored(alicePassword, static_cast<int>(std::strlen(alicePassword)), &armored[0], actualArmoredSize, 0, nullptr, &decodedSize);
        if (status != BUFFER_TOO_SMALL || decodedSize != static_cast<int>(std::strlen(message)))
        {
            std::cout << "RunPgpArmorTest: FAILED DecryptStringArmored capacity query status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> decoded(static_cast<std::size_t>(decodedSize));
        int actualDecodedSize = 0;
        status = alice.DecryptStringArmored(alicePassword, static_cast<int>(std::strlen(alicePassword)), &armored[0], actualArmoredSize, decodedSize, &decoded[0], &actualDecodedSize);
        if (status != NO_ERROR || std::string(decoded.begin(), decoded.end()) != message)
        {
            std::cout << "RunPgpArmorTest: FAILED DecryptStringArmored status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::string corrupted(armored.begin(), armored.begin() + actualArmoredSize);
        const std::size_t blankLine = corrupted.find("\r\n\r\n");
        if (blankLine == std::string::npos || blankLine + 10 >= corrupted.size())
        {
            std::cout << "RunPgpArmorTest: FAILED could not locate armor data to corrupt" << std::endl;
            return UNEXPECTED_ERROR;
        }
        char& victim = corrupted[blankLine + 8];
        victim = (victim == 'A') ? 'B' : 'A';

        int corruptedDecodedSize = 0;
        const int corruptedStatus = alice.DecryptStringArmored(alicePassword, static_cast<int>(std::strlen(alicePassword)), corrupted.c_str(),
                                                                static_cast<int>(corrupted.size()), 0, nullptr, &corruptedDecodedSize);
        if (corruptedStatus == NO_ERROR || corruptedStatus == BUFFER_TOO_SMALL)
        {
            std::cout << "RunPgpArmorTest: FAILED corrupted armor was not rejected, status=" << corruptedStatus << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunPgpArmorTest: PASSED armor round trip (" << actualArmoredSize << " bytes), corrupted armor correctly rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApiTester::RunPgpAliceBobTest(void)
{
    try
    {
        const char* documentPath = "cryptoapi_pgp_alicebob_document.bin";
        const char* documentText =
            "Quarterly Report - CONFIDENTIAL\r\n"
            "Revenue: $1,250,000\r\n"
            "Expenses: $980,000\r\n"
            "Net Profit: $270,000\r\n"
            "Prepared by: Bob\r\n";
        const std::vector<unsigned char> documentBytesToWrite(documentText, documentText + std::strlen(documentText));

        if (!WriteTesterFile(documentPath, documentBytesToWrite))
        {
            std::cout << "RunPgpAliceBobTest: FAILED to write document file" << std::endl;
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> document;
        if (!ReadTesterFile(documentPath, document))
        {
            std::cout << "RunPgpAliceBobTest: FAILED to read document file" << std::endl;
            std::remove(documentPath);
            return FILE_IO_ERROR;
        }
        std::remove(documentPath);

        CPgpEngine bob;
        CPgpEngine alice;
        CPgpEngine carol;
        CPgpEngine dave;

        const char* bobUserId   = "Bob <bob@example.com>";
        const char* aliceUserId = "Alice <alice@example.com>";
        const char* carolUserId = "Carol <carol@example.com>";
        const char* daveUserId  = "Dave <dave@example.com>";
        const char* bobPassword   = "bob-password-1";
        const char* alicePassword = "alice-password-1";
        const char* carolPassword = "carol-password-1";
        const char* davePassword  = "dave-password-1";

        int status = bob.GenerateKeyPair(bobUserId, static_cast<int>(std::strlen(bobUserId)), bobPassword, static_cast<int>(std::strlen(bobPassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob GenerateKeyPair status=" << status << std::endl;
            return status;
        }
        status = alice.GenerateKeyPair(aliceUserId, static_cast<int>(std::strlen(aliceUserId)), alicePassword, static_cast<int>(std::strlen(alicePassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED alice GenerateKeyPair status=" << status << std::endl;
            return status;
        }
        status = carol.GenerateKeyPair(carolUserId, static_cast<int>(std::strlen(carolUserId)), carolPassword, static_cast<int>(std::strlen(carolPassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED carol GenerateKeyPair status=" << status << std::endl;
            return status;
        }
        status = dave.GenerateKeyPair(daveUserId, static_cast<int>(std::strlen(daveUserId)), davePassword, static_cast<int>(std::strlen(davePassword)));
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED dave GenerateKeyPair status=" << status << std::endl;
            return status;
        }

        // Each public key is exported to a real .asc file and read back from it (same
        // write-then-read-then-remove pattern as the document above) before being handed to
        // ImportPeerPublicKey -- a real PGP public key exchange is a file, not just a buffer
        // living in the sender's own memory.
        const char* bobPubKeyPath   = "cryptoapi_pgp_alicebob_bob_pub.asc";
        const char* alicePubKeyPath = "cryptoapi_pgp_alicebob_alice_pub.asc";
        const char* carolPubKeyPath = "cryptoapi_pgp_alicebob_carol_pub.asc";
        const char* davePubKeyPath  = "cryptoapi_pgp_alicebob_dave_pub.asc";

        int bobKeySize = 0;
        bob.ExportPublicKeyArmored(0, nullptr, &bobKeySize);
        std::vector<char> bobPublicKeyOut(static_cast<std::size_t>(bobKeySize));
        int bobActualKeySize = 0;
        bob.ExportPublicKeyArmored(bobKeySize, &bobPublicKeyOut[0], &bobActualKeySize);
        if (!WriteTesterFile(bobPubKeyPath, std::vector<unsigned char>(bobPublicKeyOut.begin(), bobPublicKeyOut.begin() + bobActualKeySize)))
        {
            std::cout << "RunPgpAliceBobTest: FAILED to write bob public key file" << std::endl;
            return FILE_IO_ERROR;
        }

        int aliceKeySize = 0;
        alice.ExportPublicKeyArmored(0, nullptr, &aliceKeySize);
        std::vector<char> alicePublicKeyOut(static_cast<std::size_t>(aliceKeySize));
        int aliceActualKeySize = 0;
        alice.ExportPublicKeyArmored(aliceKeySize, &alicePublicKeyOut[0], &aliceActualKeySize);
        if (!WriteTesterFile(alicePubKeyPath, std::vector<unsigned char>(alicePublicKeyOut.begin(), alicePublicKeyOut.begin() + aliceActualKeySize)))
        {
            std::cout << "RunPgpAliceBobTest: FAILED to write alice public key file" << std::endl;
            std::remove(bobPubKeyPath);
            return FILE_IO_ERROR;
        }

        int carolKeySize = 0;
        carol.ExportPublicKeyArmored(0, nullptr, &carolKeySize);
        std::vector<char> carolPublicKeyOut(static_cast<std::size_t>(carolKeySize));
        int carolActualKeySize = 0;
        carol.ExportPublicKeyArmored(carolKeySize, &carolPublicKeyOut[0], &carolActualKeySize);
        if (!WriteTesterFile(carolPubKeyPath, std::vector<unsigned char>(carolPublicKeyOut.begin(), carolPublicKeyOut.begin() + carolActualKeySize)))
        {
            std::cout << "RunPgpAliceBobTest: FAILED to write carol public key file" << std::endl;
            std::remove(bobPubKeyPath);
            std::remove(alicePubKeyPath);
            return FILE_IO_ERROR;
        }

        int daveKeySize = 0;
        dave.ExportPublicKeyArmored(0, nullptr, &daveKeySize);
        std::vector<char> davePublicKeyOut(static_cast<std::size_t>(daveKeySize));
        int daveActualKeySize = 0;
        dave.ExportPublicKeyArmored(daveKeySize, &davePublicKeyOut[0], &daveActualKeySize);
        if (!WriteTesterFile(davePubKeyPath, std::vector<unsigned char>(davePublicKeyOut.begin(), davePublicKeyOut.begin() + daveActualKeySize)))
        {
            std::cout << "RunPgpAliceBobTest: FAILED to write dave public key file" << std::endl;
            std::remove(bobPubKeyPath);
            std::remove(alicePubKeyPath);
            std::remove(carolPubKeyPath);
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> bobPublicKey;
        std::vector<unsigned char> alicePublicKey;
        std::vector<unsigned char> carolPublicKey;
        std::vector<unsigned char> davePublicKey;
        const bool readAllPublicKeys = ReadTesterFile(bobPubKeyPath, bobPublicKey) && ReadTesterFile(alicePubKeyPath, alicePublicKey) &&
                                        ReadTesterFile(carolPubKeyPath, carolPublicKey) && ReadTesterFile(davePubKeyPath, davePublicKey);
        std::remove(bobPubKeyPath);
        std::remove(alicePubKeyPath);
        std::remove(carolPubKeyPath);
        std::remove(davePubKeyPath);
        if (!readAllPublicKeys)
        {
            std::cout << "RunPgpAliceBobTest: FAILED to read back one or more public key files" << std::endl;
            return FILE_IO_ERROR;
        }
        const int bobActualKeySizeFromFile = static_cast<int>(bobPublicKey.size());
        const int aliceActualKeySizeFromFile = static_cast<int>(alicePublicKey.size());
        const int carolActualKeySizeFromFile = static_cast<int>(carolPublicKey.size());
        const int daveActualKeySizeFromFile = static_cast<int>(davePublicKey.size());

        // Each recipient needs Bob's public key to verify his signature later.
        status = alice.ImportPeerPublicKey(&bobPublicKey[0], bobActualKeySizeFromFile);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED alice ImportPeerPublicKey(bob) status=" << status << std::endl;
            return status;
        }
        status = carol.ImportPeerPublicKey(&bobPublicKey[0], bobActualKeySizeFromFile);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED carol ImportPeerPublicKey(bob) status=" << status << std::endl;
            return status;
        }
        status = dave.ImportPeerPublicKey(&bobPublicKey[0], bobActualKeySizeFromFile);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED dave ImportPeerPublicKey(bob) status=" << status << std::endl;
            return status;
        }

        // Bob signs the document once; the same signature travels to every recipient.
        int sigSize = 0;
        bob.SignBuffer(bobPassword, static_cast<int>(std::strlen(bobPassword)), &document[0], static_cast<int>(document.size()), 0, nullptr, &sigSize);
        if (sigSize <= 0)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob SignBuffer capacity query" << std::endl;
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> signature(static_cast<std::size_t>(sigSize));
        int actualSigSize = 0;
        status = bob.SignBuffer(bobPassword, static_cast<int>(std::strlen(bobPassword)), &document[0], static_cast<int>(document.size()), sigSize, &signature[0], &actualSigSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob SignBuffer status=" << status << std::endl;
            return status;
        }

        // Frame [4-byte big-endian signature length][signature][document] -- this engine has no
        // built-in combined sign+encrypt call, so the two pieces travel together as one buffer.
        std::vector<unsigned char> combined;
        combined.push_back(static_cast<unsigned char>((actualSigSize >> 24) & 0xFF));
        combined.push_back(static_cast<unsigned char>((actualSigSize >> 16) & 0xFF));
        combined.push_back(static_cast<unsigned char>((actualSigSize >> 8) & 0xFF));
        combined.push_back(static_cast<unsigned char>(actualSigSize & 0xFF));
        combined.insert(combined.end(), signature.begin(), signature.begin() + actualSigSize);
        combined.insert(combined.end(), document.begin(), document.end());

        // Bob encrypts the same signed payload separately to each of Alice/Carol/Dave -- no
        // multi-recipient PKESK support in this engine, so "sending to 3 people" means 3
        // independent ciphertexts of the identical signed payload, not one shared ciphertext.
        status = bob.ImportPeerPublicKey(&alicePublicKey[0], aliceActualKeySizeFromFile);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob ImportPeerPublicKey(alice) status=" << status << std::endl;
            return status;
        }
        int cipherForAliceSize = 0;
        bob.EncryptBuffer(&combined[0], static_cast<int>(combined.size()), 0, nullptr, &cipherForAliceSize);
        std::vector<unsigned char> cipherForAlice(static_cast<std::size_t>(cipherForAliceSize));
        int actualCipherForAliceSize = 0;
        status = bob.EncryptBuffer(&combined[0], static_cast<int>(combined.size()), cipherForAliceSize, &cipherForAlice[0], &actualCipherForAliceSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob EncryptBuffer(for alice) status=" << status << std::endl;
            return status;
        }

        status = bob.ImportPeerPublicKey(&carolPublicKey[0], carolActualKeySizeFromFile);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob ImportPeerPublicKey(carol) status=" << status << std::endl;
            return status;
        }
        int cipherForCarolSize = 0;
        bob.EncryptBuffer(&combined[0], static_cast<int>(combined.size()), 0, nullptr, &cipherForCarolSize);
        std::vector<unsigned char> cipherForCarol(static_cast<std::size_t>(cipherForCarolSize));
        int actualCipherForCarolSize = 0;
        status = bob.EncryptBuffer(&combined[0], static_cast<int>(combined.size()), cipherForCarolSize, &cipherForCarol[0], &actualCipherForCarolSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob EncryptBuffer(for carol) status=" << status << std::endl;
            return status;
        }

        status = bob.ImportPeerPublicKey(&davePublicKey[0], daveActualKeySizeFromFile);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob ImportPeerPublicKey(dave) status=" << status << std::endl;
            return status;
        }
        int cipherForDaveSize = 0;
        bob.EncryptBuffer(&combined[0], static_cast<int>(combined.size()), 0, nullptr, &cipherForDaveSize);
        std::vector<unsigned char> cipherForDave(static_cast<std::size_t>(cipherForDaveSize));
        int actualCipherForDaveSize = 0;
        status = bob.EncryptBuffer(&combined[0], static_cast<int>(combined.size()), cipherForDaveSize, &cipherForDave[0], &actualCipherForDaveSize);
        if (status != NO_ERROR)
        {
            std::cout << "RunPgpAliceBobTest: FAILED bob EncryptBuffer(for dave) status=" << status << std::endl;
            return status;
        }

        // Alice decrypts her own copy and verifies Bob's signature.
        int alicePlainSize = 0;
        alice.DecryptBuffer(alicePassword, static_cast<int>(std::strlen(alicePassword)), &cipherForAlice[0], actualCipherForAliceSize, 0, nullptr, &alicePlainSize);
        std::vector<unsigned char> alicePlain(static_cast<std::size_t>(alicePlainSize));
        int aliceActualPlainSize = 0;
        status = alice.DecryptBuffer(alicePassword, static_cast<int>(std::strlen(alicePassword)), &cipherForAlice[0], actualCipherForAliceSize, alicePlainSize, &alicePlain[0], &aliceActualPlainSize);
        if (status != NO_ERROR || alicePlain.size() < 4)
        {
            std::cout << "RunPgpAliceBobTest: FAILED alice DecryptBuffer status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        const int aliceSigLen = (alicePlain[0] << 24) | (alicePlain[1] << 16) | (alicePlain[2] << 8) | alicePlain[3];
        if (static_cast<std::size_t>(4 + aliceSigLen) > alicePlain.size())
        {
            std::cout << "RunPgpAliceBobTest: FAILED alice combined payload malformed" << std::endl;
            return UNEXPECTED_ERROR;
        }
        const std::vector<unsigned char> aliceSignature(alicePlain.begin() + 4, alicePlain.begin() + 4 + aliceSigLen);
        const std::vector<unsigned char> aliceDocument(alicePlain.begin() + 4 + aliceSigLen, alicePlain.end());
        if (aliceDocument != document)
        {
            std::cout << "RunPgpAliceBobTest: FAILED alice recovered document does not match original" << std::endl;
            return UNEXPECTED_ERROR;
        }
        bool aliceIsValid = false;
        status = alice.VerifyBuffer(&aliceDocument[0], static_cast<int>(aliceDocument.size()), &aliceSignature[0], static_cast<int>(aliceSignature.size()), &aliceIsValid);
        if (status != NO_ERROR || !aliceIsValid)
        {
            std::cout << "RunPgpAliceBobTest: FAILED alice VerifyBuffer status=" << status << " isValid=" << aliceIsValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Carol decrypts her own copy and verifies Bob's signature.
        int carolPlainSize = 0;
        carol.DecryptBuffer(carolPassword, static_cast<int>(std::strlen(carolPassword)), &cipherForCarol[0], actualCipherForCarolSize, 0, nullptr, &carolPlainSize);
        std::vector<unsigned char> carolPlain(static_cast<std::size_t>(carolPlainSize));
        int carolActualPlainSize = 0;
        status = carol.DecryptBuffer(carolPassword, static_cast<int>(std::strlen(carolPassword)), &cipherForCarol[0], actualCipherForCarolSize, carolPlainSize, &carolPlain[0], &carolActualPlainSize);
        if (status != NO_ERROR || carolPlain.size() < 4)
        {
            std::cout << "RunPgpAliceBobTest: FAILED carol DecryptBuffer status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        const int carolSigLen = (carolPlain[0] << 24) | (carolPlain[1] << 16) | (carolPlain[2] << 8) | carolPlain[3];
        if (static_cast<std::size_t>(4 + carolSigLen) > carolPlain.size())
        {
            std::cout << "RunPgpAliceBobTest: FAILED carol combined payload malformed" << std::endl;
            return UNEXPECTED_ERROR;
        }
        const std::vector<unsigned char> carolSignature(carolPlain.begin() + 4, carolPlain.begin() + 4 + carolSigLen);
        const std::vector<unsigned char> carolDocument(carolPlain.begin() + 4 + carolSigLen, carolPlain.end());
        if (carolDocument != document)
        {
            std::cout << "RunPgpAliceBobTest: FAILED carol recovered document does not match original" << std::endl;
            return UNEXPECTED_ERROR;
        }
        bool carolIsValid = false;
        status = carol.VerifyBuffer(&carolDocument[0], static_cast<int>(carolDocument.size()), &carolSignature[0], static_cast<int>(carolSignature.size()), &carolIsValid);
        if (status != NO_ERROR || !carolIsValid)
        {
            std::cout << "RunPgpAliceBobTest: FAILED carol VerifyBuffer status=" << status << " isValid=" << carolIsValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        // Dave decrypts his own copy and verifies Bob's signature, then a tampered copy of that
        // same signature is confirmed to be correctly rejected.
        int davePlainSize = 0;
        dave.DecryptBuffer(davePassword, static_cast<int>(std::strlen(davePassword)), &cipherForDave[0], actualCipherForDaveSize, 0, nullptr, &davePlainSize);
        std::vector<unsigned char> davePlain(static_cast<std::size_t>(davePlainSize));
        int daveActualPlainSize = 0;
        status = dave.DecryptBuffer(davePassword, static_cast<int>(std::strlen(davePassword)), &cipherForDave[0], actualCipherForDaveSize, davePlainSize, &davePlain[0], &daveActualPlainSize);
        if (status != NO_ERROR || davePlain.size() < 4)
        {
            std::cout << "RunPgpAliceBobTest: FAILED dave DecryptBuffer status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }
        const int daveSigLen = (davePlain[0] << 24) | (davePlain[1] << 16) | (davePlain[2] << 8) | davePlain[3];
        if (static_cast<std::size_t>(4 + daveSigLen) > davePlain.size())
        {
            std::cout << "RunPgpAliceBobTest: FAILED dave combined payload malformed" << std::endl;
            return UNEXPECTED_ERROR;
        }
        const std::vector<unsigned char> daveSignature(davePlain.begin() + 4, davePlain.begin() + 4 + daveSigLen);
        const std::vector<unsigned char> daveDocument(davePlain.begin() + 4 + daveSigLen, davePlain.end());
        if (daveDocument != document)
        {
            std::cout << "RunPgpAliceBobTest: FAILED dave recovered document does not match original" << std::endl;
            return UNEXPECTED_ERROR;
        }
        bool daveIsValid = false;
        status = dave.VerifyBuffer(&daveDocument[0], static_cast<int>(daveDocument.size()), &daveSignature[0], static_cast<int>(daveSignature.size()), &daveIsValid);
        if (status != NO_ERROR || !daveIsValid)
        {
            std::cout << "RunPgpAliceBobTest: FAILED dave VerifyBuffer status=" << status << " isValid=" << daveIsValid << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> tamperedDaveSignature(daveSignature);
        tamperedDaveSignature[tamperedDaveSignature.size() - 1] = static_cast<unsigned char>(tamperedDaveSignature[tamperedDaveSignature.size() - 1] ^ 0xFF);
        bool tamperedIsValid = true;
        status = dave.VerifyBuffer(&daveDocument[0], static_cast<int>(daveDocument.size()), &tamperedDaveSignature[0], static_cast<int>(tamperedDaveSignature.size()), &tamperedIsValid);
        if (status != NO_ERROR || tamperedIsValid)
        {
            std::cout << "RunPgpAliceBobTest: FAILED tampered signature reported valid, status=" << status << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunPgpAliceBobTest: PASSED bob signed once (" << actualSigSize << " bytes) and encrypted separately to alice/carol/dave ("
                  << actualCipherForAliceSize << "/" << actualCipherForCarolSize << "/" << actualCipherForDaveSize
                  << " bytes); all 3 decrypted+verified the " << document.size() << "-byte document, tampered signature correctly rejected" << std::endl;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

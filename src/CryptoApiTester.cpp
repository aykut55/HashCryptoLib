#include "CryptoApiTester.h"

#include "CryptoApi.h"
#include "Definitions/Definitions.h"
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

} // namespace CryptoApiNS

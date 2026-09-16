#include "CryptoApi.h"
#include "Utils/Utils.h"
#include "Definitions/Definitions.h"
#include "Providers/CryptoProviderFactory.h"
#include "Providers/CryptoProviderRegistry.h"

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
#include <climits>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#define CRYPTOAPI_STRINGIFY_IMPL(value) #value
#define CRYPTOAPI_STRINGIFY(value) CRYPTOAPI_STRINGIFY_IMPL(value)

namespace
{

bool convertUtf8PathToWide(const char* utf8Path, std::wstring& widePath)
{
    try
    {
        if (utf8Path == nullptr)
        {
            return false;
        }

        const int widePathSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Path, -1, nullptr, 0);
        if (widePathSize <= 0)
        {
            return false;
        }

        std::vector<wchar_t> widePathBuffer(static_cast<std::size_t>(widePathSize));
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Path, -1, &widePathBuffer[0], widePathSize) <= 0)
        {
            return false;
        }

        widePath.assign(&widePathBuffer[0]);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool readFileBytes(const std::wstring& filePath, std::vector<unsigned char>& fileBuffer)
{
    try
    {
        HANDLE rawFileHandle = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawFileHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> fileHandle(rawFileHandle, &CloseHandle);
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(rawFileHandle, &fileSize) || fileSize.QuadPart < 0 || fileSize.QuadPart > INT_MAX)
        {
            return false;
        }

        fileBuffer.resize(static_cast<std::size_t>(fileSize.QuadPart));
        std::size_t bytesReadTotal = 0;
        while (bytesReadTotal < fileBuffer.size())
        {
            const std::size_t remainingBytes = fileBuffer.size() - bytesReadTotal;
            const DWORD bytesToRead = static_cast<DWORD>(remainingBytes > 1048576 ? 1048576 : remainingBytes);
            DWORD bytesRead = 0;
            if (!ReadFile(rawFileHandle, &fileBuffer[bytesReadTotal], bytesToRead, &bytesRead, nullptr) || bytesRead == 0)
            {
                return false;
            }

            bytesReadTotal += bytesRead;
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool writeFileBytes(const std::wstring& filePath, const std::vector<unsigned char>& fileBuffer)
{
    try
    {
        HANDLE rawFileHandle = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawFileHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> fileHandle(rawFileHandle, &CloseHandle);
        std::size_t bytesWrittenTotal = 0;
        while (bytesWrittenTotal < fileBuffer.size())
        {
            const std::size_t remainingBytes = fileBuffer.size() - bytesWrittenTotal;
            const DWORD bytesToWrite = static_cast<DWORD>(remainingBytes > 1048576 ? 1048576 : remainingBytes);
            DWORD bytesWritten = 0;
            if (!WriteFile(rawFileHandle, &fileBuffer[bytesWrittenTotal], bytesToWrite, &bytesWritten, nullptr) || bytesWritten == 0)
            {
                return false;
            }

            bytesWrittenTotal += bytesWritten;
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool deleteFileBestEffort(const std::wstring& filePath)
{
    return DeleteFileW(filePath.c_str()) != 0;
}
// -----------------------------------------------------------------------------

bool readFileExact(HANDLE fileHandle, unsigned char* buffer, const DWORD size)
{
    try
    {
        DWORD bytesReadTotal = 0;
        while (bytesReadTotal < size)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(fileHandle, buffer + bytesReadTotal, size - bytesReadTotal, &bytesRead, nullptr) ||
                bytesRead == 0)
            {
                return false;
            }

            bytesReadTotal += bytesRead;
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool writeFileExact(HANDLE fileHandle, const unsigned char* buffer, const DWORD size)
{
    try
    {
        DWORD bytesWrittenTotal = 0;
        while (bytesWrittenTotal < size)
        {
            DWORD bytesWritten = 0;
            if (!WriteFile(fileHandle, buffer + bytesWrittenTotal, size - bytesWrittenTotal, &bytesWritten, nullptr) ||
                bytesWritten == 0)
            {
                return false;
            }

            bytesWrittenTotal += bytesWritten;
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

void writeUInt32(unsigned char* buffer, const unsigned int value)
{
    buffer[0] = static_cast<unsigned char>(value);
    buffer[1] = static_cast<unsigned char>(value >> 8);
    buffer[2] = static_cast<unsigned char>(value >> 16);
    buffer[3] = static_cast<unsigned char>(value >> 24);
}
// -----------------------------------------------------------------------------

unsigned int readUInt32(const unsigned char* buffer)
{
    return static_cast<unsigned int>(buffer[0]) |
           (static_cast<unsigned int>(buffer[1]) << 8) |
           (static_cast<unsigned int>(buffer[2]) << 16) |
           (static_cast<unsigned int>(buffer[3]) << 24);
}
// -----------------------------------------------------------------------------

const unsigned int PASSWORD_SALT_SIZE = 16;
const unsigned int PASSWORD_KDF_ITERATIONS = 600000;
const unsigned int   FILE_CHUNK_SIZE = 1048576 * 0 + 1024 * 1; // 1 MiB plaintext chunk size for streaming file operations.
const unsigned int BUFFER_CHUNK_SIZE = 1048576 * 0 + 1024 * 1; // 1 MiB plaintext chunk size for EncryptBuffer/EncryptString.
const unsigned int LEGACY_MAC_KEY_SIZE = 32; // HMAC-SHA256 key size used by EncryptLegacyBuffer/DecryptLegacyBuffer.

bool constantTimeEquals(const unsigned char* left, const unsigned char* right, const unsigned int size)
{
    unsigned char difference = 0;
    for (unsigned int index = 0; index < size; ++index)
    {
        difference |= static_cast<unsigned char>(left[index] ^ right[index]);
    }

    return difference == 0;
}
// -----------------------------------------------------------------------------

} // namespace

namespace CryptoApiNS
{

CCryptoApi::~CCryptoApi()
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi() : providerKind_(PROVIDER_MICROSOFT), aeadAlgorithm_(AEAD_AES_256_GCM), asymmetricAlgorithm_(ASYMMETRIC_RSA_2048), legacyAlgorithm_(LEGACY_AES_256_CBC), hashAlgorithm_(HASH_SHA256), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(aeadAlgorithm), asymmetricAlgorithm_(ASYMMETRIC_RSA_2048), legacyAlgorithm_(LEGACY_AES_256_CBC), hashAlgorithm_(HASH_SHA256), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const HashAlgorithm hashAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(AEAD_AES_256_GCM), asymmetricAlgorithm_(ASYMMETRIC_RSA_2048), legacyAlgorithm_(LEGACY_AES_256_CBC), hashAlgorithm_(hashAlgorithm), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const AsymmetricAlgorithm asymmetricAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(AEAD_AES_256_GCM), asymmetricAlgorithm_(asymmetricAlgorithm), legacyAlgorithm_(LEGACY_AES_256_CBC), hashAlgorithm_(HASH_SHA256), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const LegacySymmetricAlgorithm legacyAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(AEAD_AES_256_GCM), asymmetricAlgorithm_(ASYMMETRIC_RSA_2048), legacyAlgorithm_(legacyAlgorithm), hashAlgorithm_(HASH_SHA256), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const SignatureAlgorithm signatureAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(AEAD_AES_256_GCM), asymmetricAlgorithm_(ASYMMETRIC_RSA_2048), legacyAlgorithm_(LEGACY_AES_256_CBC), hashAlgorithm_(HASH_SHA256), signatureAlgorithm_(signatureAlgorithm), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const KeyAgreementAlgorithm keyAgreementAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(AEAD_AES_256_GCM), asymmetricAlgorithm_(ASYMMETRIC_RSA_2048), legacyAlgorithm_(LEGACY_AES_256_CBC), hashAlgorithm_(HASH_SHA256), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(keyAgreementAlgorithm)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(aeadAlgorithm), asymmetricAlgorithm_(asymmetricAlgorithm), legacyAlgorithm_(LEGACY_AES_256_CBC), hashAlgorithm_(HASH_SHA256), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(aeadAlgorithm), asymmetricAlgorithm_(asymmetricAlgorithm), legacyAlgorithm_(legacyAlgorithm), hashAlgorithm_(HASH_SHA256), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(aeadAlgorithm), asymmetricAlgorithm_(asymmetricAlgorithm), legacyAlgorithm_(legacyAlgorithm), hashAlgorithm_(hashAlgorithm), signatureAlgorithm_(SIGNATURE_ECDSA_P256_SHA256), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(aeadAlgorithm), asymmetricAlgorithm_(asymmetricAlgorithm), legacyAlgorithm_(legacyAlgorithm), hashAlgorithm_(hashAlgorithm), signatureAlgorithm_(signatureAlgorithm), keyAgreementAlgorithm_(KEYAGREEMENT_ECDH_P256)
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm, const KeyAgreementAlgorithm keyAgreementAlgorithm) : providerKind_(providerKind), aeadAlgorithm_(aeadAlgorithm), asymmetricAlgorithm_(asymmetricAlgorithm), legacyAlgorithm_(legacyAlgorithm), hashAlgorithm_(hashAlgorithm), signatureAlgorithm_(signatureAlgorithm), keyAgreementAlgorithm_(keyAgreementAlgorithm)
{
}
// -----------------------------------------------------------------------------

const char* CCryptoApi::GetVersion(void) const
{
    try
    {
        static const std::string version = CRYPTOAPI_STRINGIFY(CRYPTOAPI_VERSION_MAJOR) "."
                                           CRYPTOAPI_STRINGIFY(CRYPTOAPI_VERSION_MINOR)
                                           "." CRYPTOAPI_STRINGIFY(CRYPTOAPI_VERSION_BUILD_NUMBER)
                                           " (" + std::string(CUtils::FormatBuildDate())
                                           + " " CRYPTOAPI_BUILD_TIME ")";

        return version.c_str();
    }
    catch (...)
    {
        return "";
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::encryptBuffer(const unsigned char* key, const int keySize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (key == nullptr || keySize <= 0 || inputBufferSize < 0 ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<IAeadCipher> cipher = providerFactory->CreateAeadCipher(aeadAlgorithm_);
        std::unique_ptr<IRandomSource> randomSource = providerFactory->CreateRandomSource();
        if (!cipher || !randomSource)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int nonceSize = cipher->GetNonceSize();
        const unsigned int tagSize = cipher->GetTagSize();
        const long long requiredSizeLL = static_cast<long long>(inputBufferSize) +
                                         static_cast<long long>(nonceSize) +
                                         static_cast<long long>(tagSize);
        if (requiredSizeLL > INT_MAX)
        {
            return INVALID_ARGUMENT;
        }

        const int requiredSize = static_cast<int>(requiredSizeLL);
        if (outputBufferCapacity < requiredSize || outputBuffer == nullptr)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        if (!cipher->SetKey(key, static_cast<unsigned int>(keySize)))
        {
            return INVALID_ARGUMENT;
        }

        unsigned char* noncePtr = outputBuffer;
        unsigned char* ciphertextPtr = outputBuffer + nonceSize;
        unsigned char* tagPtr = ciphertextPtr + inputBufferSize;

        if (!randomSource->GenerateRandomBytes(noncePtr, nonceSize))
        {
            return UNEXPECTED_ERROR;
        }

        if (!cipher->Encrypt(noncePtr, nonceSize,
                            inputBuffer, static_cast<unsigned int>(inputBufferSize),
                            ciphertextPtr,
                            tagPtr, tagSize))
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = requiredSize;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::decryptBuffer(const unsigned char* key, const int keySize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (key == nullptr || keySize <= 0 || inputBuffer == nullptr || inputBufferSize < 0)
        {
            return INVALID_ARGUMENT;
        }

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<IAeadCipher> cipher = providerFactory->CreateAeadCipher(aeadAlgorithm_);
        if (!cipher)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int nonceSize = cipher->GetNonceSize();
        const unsigned int tagSize = cipher->GetTagSize();
        const unsigned int overhead = nonceSize + tagSize;
        if (static_cast<unsigned int>(inputBufferSize) < overhead)
        {
            return INVALID_DATA;
        }

        const int requiredSize = inputBufferSize - static_cast<int>(overhead);
        if (outputBufferCapacity < requiredSize || (requiredSize > 0 && outputBuffer == nullptr))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        if (!cipher->SetKey(key, static_cast<unsigned int>(keySize)))
        {
            return INVALID_ARGUMENT;
        }

        const unsigned char* noncePtr = inputBuffer;
        const unsigned char* ciphertextPtr = inputBuffer + nonceSize;
        const unsigned char* tagPtr = ciphertextPtr + requiredSize;

        if (!cipher->Decrypt(noncePtr, nonceSize,
                            ciphertextPtr, static_cast<unsigned int>(requiredSize),
                            tagPtr, tagSize,
                            outputBuffer))
        {
            return INVALID_DATA;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = requiredSize;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::encryptBuffer(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (password == nullptr || passwordSize <= 0 || inputBufferSize < 0 ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<IAeadCipher> cipher = providerFactory->CreateAeadCipher(aeadAlgorithm_);
        std::unique_ptr<IRandomSource> randomSource = providerFactory->CreateRandomSource();
        std::unique_ptr<IKeyDerivation> keyDerivation = providerFactory->CreateKeyDerivation();
        if (!cipher || !randomSource || !keyDerivation)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int nonceSize = cipher->GetNonceSize();
        const unsigned int tagSize = cipher->GetTagSize();
        const unsigned int keySize = cipher->GetKeySize();
        const unsigned int recordOverhead = 4u + nonceSize + tagSize;
        const unsigned int chunkCount = inputBufferSize > 0
            ? static_cast<unsigned int>((static_cast<long long>(inputBufferSize) + BUFFER_CHUNK_SIZE - 1) / BUFFER_CHUNK_SIZE)
            : 0;

        const long long requiredSizeLL = static_cast<long long>(PASSWORD_SALT_SIZE) +
                                         static_cast<long long>(inputBufferSize) +
                                         static_cast<long long>(chunkCount) * static_cast<long long>(recordOverhead);
        if (requiredSizeLL > INT_MAX)
        {
            return INVALID_ARGUMENT;
        }

        const int requiredSize = static_cast<int>(requiredSizeLL);
        if (outputBufferCapacity < requiredSize || outputBuffer == nullptr)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        unsigned char* saltPtr = outputBuffer;
        if (!randomSource->GenerateRandomBytes(saltPtr, PASSWORD_SALT_SIZE))
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> key(keySize);
        if (!keyDerivation->DerivePasswordKey(password, static_cast<unsigned int>(passwordSize),
                                             saltPtr, PASSWORD_SALT_SIZE,
                                             PASSWORD_KDF_ITERATIONS,
                                             &key[0], keySize))
        {
            SecureZeroMemory(&key[0], key.size());
            return UNEXPECTED_ERROR;
        }

        unsigned char* writePtr = outputBuffer + PASSWORD_SALT_SIZE;
        const unsigned long long totalBytes = static_cast<unsigned long long>(inputBufferSize);
        unsigned long long processedBytes = 0;

        for (unsigned int chunkIndex = 0; chunkIndex < chunkCount; ++chunkIndex)
        {
            const unsigned int offset = chunkIndex * BUFFER_CHUNK_SIZE;
            const unsigned int remainingInput = static_cast<unsigned int>(inputBufferSize) - offset;
            const unsigned int chunkSize = remainingInput < BUFFER_CHUNK_SIZE ? remainingInput : BUFFER_CHUNK_SIZE;

            int chunkOutputSize = 0;
            const int chunkStatus = encryptBuffer(&key[0], static_cast<int>(keySize),
                                                  inputBuffer + offset, static_cast<int>(chunkSize),
                                                  static_cast<int>(chunkSize + nonceSize + tagSize),
                                                  writePtr + 4,
                                                  &chunkOutputSize);
            if (chunkStatus != NO_ERROR)
            {
                SecureZeroMemory(&key[0], key.size());
                if (outputBufferSize)
                {
                    *outputBufferSize = 0;
                }

                return chunkStatus;
            }

            writeUInt32(writePtr, chunkSize);
            writePtr += 4 + chunkOutputSize;
            processedBytes += chunkSize;

            if (onProgress)
            {
                const double percentage = totalBytes > 0
                    ? (static_cast<double>(processedBytes) / static_cast<double>(totalBytes)) * 100.0
                    : 0.0;
                if (!onProgress(processedBytes, totalBytes, percentage, progressUserData))
                {
                    SecureZeroMemory(&key[0], key.size());
                    if (outputBufferSize)
                    {
                        *outputBufferSize = 0;
                    }

                    return OPERATION_CANCELLED;
                }
            }
        }

        SecureZeroMemory(&key[0], key.size());
        if (outputBufferSize)
        {
            *outputBufferSize = requiredSize;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::decryptBuffer(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (password == nullptr || passwordSize <= 0 || inputBuffer == nullptr || inputBufferSize < 0)
        {
            return INVALID_ARGUMENT;
        }

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<IAeadCipher> cipher = providerFactory->CreateAeadCipher(aeadAlgorithm_);
        std::unique_ptr<IKeyDerivation> keyDerivation = providerFactory->CreateKeyDerivation();
        if (!cipher || !keyDerivation)
        {
            return UNEXPECTED_ERROR;
        }

        if (static_cast<unsigned int>(inputBufferSize) < PASSWORD_SALT_SIZE)
        {
            return INVALID_DATA;
        }

        const unsigned int keySize = cipher->GetKeySize();
        const unsigned int nonceSize = cipher->GetNonceSize();
        const unsigned int tagSize = cipher->GetTagSize();
        const unsigned long long totalInputSize = static_cast<unsigned long long>(inputBufferSize);

        // First pass: validate the length-prefixed record framing and compute the required
        // plaintext size, without deriving the key or performing any crypto work.
        unsigned long long scanPos = PASSWORD_SALT_SIZE;
        long long requiredSizeLL = 0;
        while (scanPos < totalInputSize)
        {
            if (totalInputSize - scanPos < 4)
            {
                return INVALID_DATA;
            }

            const unsigned int chunkPlainSize = readUInt32(inputBuffer + scanPos);
            scanPos += 4;
            if (chunkPlainSize > BUFFER_CHUNK_SIZE)
            {
                return INVALID_DATA;
            }

            const unsigned long long recordSize = static_cast<unsigned long long>(chunkPlainSize) +
                                                  static_cast<unsigned long long>(nonceSize) +
                                                  static_cast<unsigned long long>(tagSize);
            if (recordSize > totalInputSize - scanPos)
            {
                return INVALID_DATA;
            }

            scanPos += recordSize;
            requiredSizeLL += chunkPlainSize;
            if (requiredSizeLL > INT_MAX)
            {
                return INVALID_ARGUMENT;
            }
        }

        const int requiredSize = static_cast<int>(requiredSizeLL);
        if (outputBufferCapacity < requiredSize || (requiredSize > 0 && outputBuffer == nullptr))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        const unsigned char* saltPtr = inputBuffer;
        std::vector<unsigned char> key(keySize);
        if (!keyDerivation->DerivePasswordKey(password, static_cast<unsigned int>(passwordSize),
                                             saltPtr, PASSWORD_SALT_SIZE,
                                             PASSWORD_KDF_ITERATIONS,
                                             &key[0], keySize))
        {
            SecureZeroMemory(&key[0], key.size());
            return UNEXPECTED_ERROR;
        }

        unsigned long long readPos = PASSWORD_SALT_SIZE;
        unsigned char* writePtr = outputBuffer;
        unsigned long long processedBytes = 0;

        while (readPos < totalInputSize)
        {
            const unsigned int chunkPlainSize = readUInt32(inputBuffer + readPos);
            readPos += 4;
            const unsigned int recordSize = chunkPlainSize + nonceSize + tagSize;

            int chunkOutputSize = 0;
            const int chunkStatus = decryptBuffer(&key[0], static_cast<int>(keySize),
                                                  inputBuffer + readPos, static_cast<int>(recordSize),
                                                  static_cast<int>(chunkPlainSize),
                                                  writePtr,
                                                  &chunkOutputSize);
            if (chunkStatus != NO_ERROR || static_cast<unsigned int>(chunkOutputSize) != chunkPlainSize)
            {
                SecureZeroMemory(&key[0], key.size());
                if (outputBufferSize)
                {
                    *outputBufferSize = 0;
                }

                return chunkStatus != NO_ERROR ? chunkStatus : INVALID_DATA;
            }

            readPos += recordSize;
            writePtr += chunkOutputSize;
            processedBytes += 4 + recordSize;

            if (onProgress)
            {
                const double percentage = totalInputSize > 0
                    ? (static_cast<double>(processedBytes) / static_cast<double>(totalInputSize)) * 100.0
                    : 0.0;
                if (!onProgress(processedBytes, totalInputSize, percentage, progressUserData))
                {
                    SecureZeroMemory(&key[0], key.size());
                    if (outputBufferSize)
                    {
                        *outputBufferSize = 0;
                    }

                    return OPERATION_CANCELLED;
                }
            }
        }

        SecureZeroMemory(&key[0], key.size());
        if (outputBufferSize)
        {
            *outputBufferSize = requiredSize;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::EncryptBuffer(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        return encryptBuffer(password,
                            passwordSize,
                            inputBuffer,
                            inputBufferSize,
                            outputBufferCapacity,
                            outputBuffer,
                            outputBufferSize,
                            onProgress,
                            progressUserData);
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::DecryptBuffer(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        return decryptBuffer(password,
                            passwordSize,
                            inputBuffer,
                            inputBufferSize,
                            outputBufferCapacity,
                            outputBuffer,
                            outputBufferSize,
                            onProgress,
                            progressUserData);
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::EncryptBytes(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        return encryptBuffer(password,
                            passwordSize,
                            inputBuffer,
                            inputBufferSize,
                            outputBufferCapacity,
                            outputBuffer,
                            outputBufferSize,
                            onProgress,
                            progressUserData);
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::DecryptBytes(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        return decryptBuffer(password,
                            passwordSize,
                            inputBuffer,
                            inputBufferSize,
                            outputBufferCapacity,
                            outputBuffer,
                            outputBufferSize,
                            onProgress,
                            progressUserData);
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::EncryptString(const char* password, const int passwordSize, const char* inputString, const int inputStringSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        return encryptBuffer(password,
                            passwordSize,
                            reinterpret_cast<const unsigned char*>(inputString),
                            inputStringSize,
                            outputBufferCapacity,
                            outputBuffer,
                            outputBufferSize,
                            onProgress,
                            progressUserData);
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::DecryptString(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputStringBufferCapacity, char* outputStringBuffer, int* outputStringSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        return decryptBuffer(password,
                            passwordSize,
                            inputBuffer,
                            inputBufferSize,
                            outputStringBufferCapacity,
                            reinterpret_cast<unsigned char*>(outputStringBuffer),
                            outputStringSize,
                            onProgress,
                            progressUserData);
    }
    catch (...)
    {
        if (outputStringSize)
        {
            *outputStringSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::EncryptFile(const char* password, const char* inputFilePath, const char* outputFilePath, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (password == nullptr || inputFilePath == nullptr || outputFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const std::size_t passwordSizeValue = std::strlen(password);
        if (passwordSizeValue == 0 || passwordSizeValue > static_cast<std::size_t>(INT_MAX))
        {
            return INVALID_ARGUMENT;
        }

        std::wstring wideInputFilePath;
        std::wstring wideOutputFilePath;
        if (!convertUtf8PathToWide(inputFilePath, wideInputFilePath) ||
            !convertUtf8PathToWide(outputFilePath, wideOutputFilePath))
        {
            return INVALID_ARGUMENT;
        }

        HANDLE rawInputHandle = CreateFileW(wideInputFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawInputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> inputHandle(rawInputHandle, &CloseHandle);

        HANDLE rawOutputHandle = CreateFileW(wideOutputFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawOutputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> outputHandle(rawOutputHandle, &CloseHandle);

        LARGE_INTEGER inputFileSize;
        inputFileSize.QuadPart = 0;
        GetFileSizeEx(rawInputHandle, &inputFileSize);
        const unsigned long long totalBytes = static_cast<unsigned long long>(inputFileSize.QuadPart);
        unsigned long long processedBytes = 0;

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<IAeadCipher> cipher = providerFactory->CreateAeadCipher(aeadAlgorithm_);
        std::unique_ptr<IRandomSource> randomSource = providerFactory->CreateRandomSource();
        std::unique_ptr<IKeyDerivation> keyDerivation = providerFactory->CreateKeyDerivation();
        if (!cipher || !randomSource || !keyDerivation)
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        const unsigned int keySize = cipher->GetKeySize();
        std::vector<unsigned char> salt(PASSWORD_SALT_SIZE);
        if (!randomSource->GenerateRandomBytes(&salt[0], PASSWORD_SALT_SIZE) ||
            !writeFileExact(rawOutputHandle, &salt[0], PASSWORD_SALT_SIZE))
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> key(keySize);
        if (!keyDerivation->DerivePasswordKey(password, static_cast<unsigned int>(passwordSizeValue),
                                             &salt[0], PASSWORD_SALT_SIZE,
                                             PASSWORD_KDF_ITERATIONS,
                                             &key[0], keySize))
        {
            SecureZeroMemory(&key[0], key.size());
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> plaintextChunk(FILE_CHUNK_SIZE);
        std::vector<unsigned char> encryptedChunk(FILE_CHUNK_SIZE + cipher->GetNonceSize() + cipher->GetTagSize());

        for (;;)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(rawInputHandle, &plaintextChunk[0], static_cast<DWORD>(plaintextChunk.size()), &bytesRead, nullptr))
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return FILE_IO_ERROR;
            }

            if (bytesRead == 0)
            {
                break;
            }

            int encryptedChunkSize = 0;
            const int encryptStatus = encryptBuffer(&key[0], static_cast<int>(keySize),
                                                    &plaintextChunk[0], static_cast<int>(bytesRead),
                                                    static_cast<int>(encryptedChunk.size()),
                                                    &encryptedChunk[0],
                                                    &encryptedChunkSize);
            if (encryptStatus != NO_ERROR)
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return encryptStatus;
            }

            unsigned char lengthPrefix[4];
            writeUInt32(lengthPrefix, bytesRead);
            if (!writeFileExact(rawOutputHandle, lengthPrefix, sizeof(lengthPrefix)) ||
                !writeFileExact(rawOutputHandle, &encryptedChunk[0], static_cast<DWORD>(encryptedChunkSize)))
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return FILE_IO_ERROR;
            }

            processedBytes += bytesRead;
            if (onProgress)
            {
                const double percentage = totalBytes > 0
                    ? (static_cast<double>(processedBytes) / static_cast<double>(totalBytes)) * 100.0
                    : 0.0;
                if (!onProgress(processedBytes, totalBytes, percentage, progressUserData))
                {
                    SecureZeroMemory(&key[0], key.size());
                    outputHandle.reset();
                    deleteFileBestEffort(wideOutputFilePath);
                    return OPERATION_CANCELLED;
                }
            }
        }

        SecureZeroMemory(&key[0], key.size());

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::DecryptFile(const char* password, const char* inputFilePath, const char* outputFilePath, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (password == nullptr || inputFilePath == nullptr || outputFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const std::size_t passwordSizeValue = std::strlen(password);
        if (passwordSizeValue == 0 || passwordSizeValue > static_cast<std::size_t>(INT_MAX))
        {
            return INVALID_ARGUMENT;
        }

        std::wstring wideInputFilePath;
        std::wstring wideOutputFilePath;
        if (!convertUtf8PathToWide(inputFilePath, wideInputFilePath) ||
            !convertUtf8PathToWide(outputFilePath, wideOutputFilePath))
        {
            return INVALID_ARGUMENT;
        }

        HANDLE rawInputHandle = CreateFileW(wideInputFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawInputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> inputHandle(rawInputHandle, &CloseHandle);

        HANDLE rawOutputHandle = CreateFileW(wideOutputFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawOutputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> outputHandle(rawOutputHandle, &CloseHandle);

        LARGE_INTEGER inputFileSize;
        inputFileSize.QuadPart = 0;
        GetFileSizeEx(rawInputHandle, &inputFileSize);
        const unsigned long long totalBytes = static_cast<unsigned long long>(inputFileSize.QuadPart);
        unsigned long long processedBytes = 0;

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<IAeadCipher> cipher = providerFactory->CreateAeadCipher(aeadAlgorithm_);
        std::unique_ptr<IKeyDerivation> keyDerivation = providerFactory->CreateKeyDerivation();
        if (!cipher || !keyDerivation)
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        const unsigned int keySize = cipher->GetKeySize();
        const unsigned int nonceSize = cipher->GetNonceSize();
        const unsigned int tagSize = cipher->GetTagSize();

        std::vector<unsigned char> salt(PASSWORD_SALT_SIZE);
        if (!readFileExact(rawInputHandle, &salt[0], PASSWORD_SALT_SIZE))
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return INVALID_DATA;
        }

        processedBytes += PASSWORD_SALT_SIZE;

        std::vector<unsigned char> key(keySize);
        if (!keyDerivation->DerivePasswordKey(password, static_cast<unsigned int>(passwordSizeValue),
                                             &salt[0], PASSWORD_SALT_SIZE,
                                             PASSWORD_KDF_ITERATIONS,
                                             &key[0], keySize))
        {
            SecureZeroMemory(&key[0], key.size());
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> encryptedChunk(FILE_CHUNK_SIZE + nonceSize + tagSize);
        std::vector<unsigned char> plaintextChunk(FILE_CHUNK_SIZE);

        for (;;)
        {
            unsigned char lengthPrefix[4];
            DWORD prefixBytesRead = 0;
            if (!ReadFile(rawInputHandle, lengthPrefix, sizeof(lengthPrefix), &prefixBytesRead, nullptr))
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return FILE_IO_ERROR;
            }

            if (prefixBytesRead == 0)
            {
                break;
            }

            if (prefixBytesRead != sizeof(lengthPrefix))
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return INVALID_DATA;
            }

            const unsigned int plaintextChunkSize = readUInt32(lengthPrefix);
            if (plaintextChunkSize > FILE_CHUNK_SIZE)
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return INVALID_DATA;
            }

            const unsigned int encryptedChunkSize = plaintextChunkSize + nonceSize + tagSize;
            if (!readFileExact(rawInputHandle, &encryptedChunk[0], encryptedChunkSize))
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return INVALID_DATA;
            }

            int decryptedChunkSize = 0;
            const int decryptStatus = decryptBuffer(&key[0], static_cast<int>(keySize),
                                                    &encryptedChunk[0], static_cast<int>(encryptedChunkSize),
                                                    static_cast<int>(plaintextChunk.size()),
                                                    &plaintextChunk[0],
                                                    &decryptedChunkSize);
            if (decryptStatus != NO_ERROR || static_cast<unsigned int>(decryptedChunkSize) != plaintextChunkSize)
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return decryptStatus != NO_ERROR ? decryptStatus : INVALID_DATA;
            }

            if (!writeFileExact(rawOutputHandle, &plaintextChunk[0], static_cast<DWORD>(decryptedChunkSize)))
            {
                SecureZeroMemory(&key[0], key.size());
                outputHandle.reset();
                deleteFileBestEffort(wideOutputFilePath);
                return FILE_IO_ERROR;
            }

            processedBytes += sizeof(lengthPrefix) + encryptedChunkSize;
            if (onProgress)
            {
                const double percentage = totalBytes > 0
                    ? (static_cast<double>(processedBytes) / static_cast<double>(totalBytes)) * 100.0
                    : 0.0;
                if (!onProgress(processedBytes, totalBytes, percentage, progressUserData))
                {
                    SecureZeroMemory(&key[0], key.size());
                    outputHandle.reset();
                    deleteFileBestEffort(wideOutputFilePath);
                    return OPERATION_CANCELLED;
                }
            }
        }

        SecureZeroMemory(&key[0], key.size());

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::GenerateAsymmetricKeyPair(void)
{
    try
    {
        if (!asymmetricCipher_)
        {
            std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
            if (!providerFactory)
            {
                return UNEXPECTED_ERROR;
            }

            asymmetricCipher_ = providerFactory->CreateAsymmetricCipher(asymmetricAlgorithm_);
            if (!asymmetricCipher_)
            {
                return UNEXPECTED_ERROR;
            }
        }

        return asymmetricCipher_->GenerateKeyPair() ? NO_ERROR : UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::GetMaxAsymmetricPlaintextSize(void) const
{
    try
    {
        return asymmetricCipher_ ? static_cast<int>(asymmetricCipher_->GetMaxPlaintextSize()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::GetAsymmetricCiphertextSize(void) const
{
    try
    {
        return asymmetricCipher_ ? static_cast<int>(asymmetricCipher_->GetCiphertextSize()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::EncryptWithPublicKey(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        if (!asymmetricCipher_)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int requiredSize = asymmetricCipher_->GetCiphertextSize();
        if (requiredSize == 0)
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(requiredSize))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = static_cast<int>(requiredSize);
            }

            return BUFFER_TOO_SMALL;
        }

        unsigned int actualSize = 0;
        if (!asymmetricCipher_->Encrypt(inputBuffer, static_cast<unsigned int>(inputBufferSize),
                                        outputBuffer, static_cast<unsigned int>(outputBufferCapacity),
                                        &actualSize))
        {
            return INVALID_ARGUMENT;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(actualSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::DecryptWithPrivateKey(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        if (!asymmetricCipher_)
        {
            return UNEXPECTED_ERROR;
        }

        unsigned int requiredSize = 0;
        asymmetricCipher_->Decrypt(inputBuffer, static_cast<unsigned int>(inputBufferSize), nullptr, 0, &requiredSize);

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(requiredSize))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = static_cast<int>(requiredSize);
            }

            return BUFFER_TOO_SMALL;
        }

        unsigned int actualSize = 0;
        if (!asymmetricCipher_->Decrypt(inputBuffer, static_cast<unsigned int>(inputBufferSize),
                                        outputBuffer, static_cast<unsigned int>(outputBufferCapacity),
                                        &actualSize))
        {
            return INVALID_DATA;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(actualSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::EncryptLegacyBuffer(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (password == nullptr || passwordSize <= 0 || inputBufferSize < 0 ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<ILegacyCipher> legacyCipher = providerFactory->CreateLegacyCipher(legacyAlgorithm_);
        std::unique_ptr<IMacService> macService = providerFactory->CreateMacService();
        std::unique_ptr<IRandomSource> randomSource = providerFactory->CreateRandomSource();
        std::unique_ptr<IKeyDerivation> keyDerivation = providerFactory->CreateKeyDerivation();
        if (!legacyCipher || !macService || !randomSource || !keyDerivation)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int keySize = legacyCipher->GetKeySize();
        const unsigned int ivSize = legacyCipher->GetIvSize();
        const unsigned int macSize = macService->GetMacSize();

        // Some providers (e.g. Microsoft/CNG's BCryptEncrypt) require a key handle to be set even
        // for a size-only query; content is irrelevant for CBC/ECB padding arithmetic, so a dummy
        // key is enough here. The real key (derived from the real salt) is set below, once the
        // capacity check has passed and salt generation is worth paying for.
        const std::vector<unsigned char> dummyKey(keySize, 0);
        legacyCipher->SetKey(dummyKey.empty() ? nullptr : &dummyKey[0], keySize);

        std::vector<unsigned char> dummyIv(ivSize, 0);
        unsigned int requiredCiphertextSize = 0;
        legacyCipher->Encrypt(ivSize > 0 ? &dummyIv[0] : nullptr, ivSize,
                              inputBuffer, static_cast<unsigned int>(inputBufferSize),
                              nullptr, 0, &requiredCiphertextSize);

        const long long requiredSizeLL = static_cast<long long>(PASSWORD_SALT_SIZE) +
                                         static_cast<long long>(ivSize) +
                                         static_cast<long long>(requiredCiphertextSize) +
                                         static_cast<long long>(macSize);
        if (requiredSizeLL > INT_MAX)
        {
            return INVALID_ARGUMENT;
        }

        const int requiredSize = static_cast<int>(requiredSizeLL);
        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        unsigned char* saltPtr = outputBuffer;
        if (!randomSource->GenerateRandomBytes(saltPtr, PASSWORD_SALT_SIZE))
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> combinedKey(static_cast<std::size_t>(keySize) + LEGACY_MAC_KEY_SIZE);
        if (!keyDerivation->DerivePasswordKey(password, static_cast<unsigned int>(passwordSize),
                                              saltPtr, PASSWORD_SALT_SIZE,
                                              PASSWORD_KDF_ITERATIONS,
                                              &combinedKey[0], static_cast<unsigned int>(combinedKey.size())))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return UNEXPECTED_ERROR;
        }

        const unsigned char* cipherKey = &combinedKey[0];
        const unsigned char* macKey = &combinedKey[keySize];

        if (!legacyCipher->SetKey(cipherKey, keySize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return UNEXPECTED_ERROR;
        }

        unsigned char* ivPtr = outputBuffer + PASSWORD_SALT_SIZE;
        if (ivSize > 0 && !randomSource->GenerateRandomBytes(ivPtr, ivSize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return UNEXPECTED_ERROR;
        }

        unsigned char* ciphertextPtr = ivPtr + ivSize;
        unsigned int actualCiphertextSize = 0;
        if (!legacyCipher->Encrypt(ivSize > 0 ? ivPtr : nullptr, ivSize,
                                   inputBuffer, static_cast<unsigned int>(inputBufferSize),
                                   ciphertextPtr, requiredCiphertextSize, &actualCiphertextSize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return UNEXPECTED_ERROR;
        }

        const unsigned int macInputSize = PASSWORD_SALT_SIZE + ivSize + actualCiphertextSize;
        unsigned char* macPtr = outputBuffer + macInputSize;
        if (!macService->ComputeMac(macKey, LEGACY_MAC_KEY_SIZE, outputBuffer, macInputSize, macPtr, macSize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return UNEXPECTED_ERROR;
        }

        SecureZeroMemory(&combinedKey[0], combinedKey.size());

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(macInputSize + macSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::DecryptLegacyBuffer(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (password == nullptr || passwordSize <= 0 || inputBuffer == nullptr || inputBufferSize < 0)
        {
            return INVALID_ARGUMENT;
        }

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<ILegacyCipher> legacyCipher = providerFactory->CreateLegacyCipher(legacyAlgorithm_);
        std::unique_ptr<IMacService> macService = providerFactory->CreateMacService();
        std::unique_ptr<IKeyDerivation> keyDerivation = providerFactory->CreateKeyDerivation();
        if (!legacyCipher || !macService || !keyDerivation)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int keySize = legacyCipher->GetKeySize();
        const unsigned int ivSize = legacyCipher->GetIvSize();
        const unsigned int macSize = macService->GetMacSize();
        const unsigned int overhead = PASSWORD_SALT_SIZE + ivSize + macSize;

        if (static_cast<unsigned int>(inputBufferSize) < overhead)
        {
            return INVALID_DATA;
        }

        const unsigned char* saltPtr = inputBuffer;
        const unsigned char* ivPtr = inputBuffer + PASSWORD_SALT_SIZE;
        const unsigned int ciphertextSize = static_cast<unsigned int>(inputBufferSize) - overhead;
        const unsigned char* ciphertextPtr = ivPtr + ivSize;
        const unsigned int macInputSize = static_cast<unsigned int>(inputBufferSize) - macSize;
        const unsigned char* receivedMacPtr = inputBuffer + macInputSize;

        std::vector<unsigned char> combinedKey(static_cast<std::size_t>(keySize) + LEGACY_MAC_KEY_SIZE);
        if (!keyDerivation->DerivePasswordKey(password, static_cast<unsigned int>(passwordSize),
                                              saltPtr, PASSWORD_SALT_SIZE,
                                              PASSWORD_KDF_ITERATIONS,
                                              &combinedKey[0], static_cast<unsigned int>(combinedKey.size())))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return UNEXPECTED_ERROR;
        }

        const unsigned char* cipherKey = &combinedKey[0];
        const unsigned char* macKey = &combinedKey[keySize];

        std::vector<unsigned char> computedMac(macSize);
        if (!macService->ComputeMac(macKey, LEGACY_MAC_KEY_SIZE, inputBuffer, macInputSize, &computedMac[0], macSize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return UNEXPECTED_ERROR;
        }

        if (!constantTimeEquals(&computedMac[0], receivedMacPtr, macSize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return INVALID_DATA;
        }

        if (!legacyCipher->SetKey(cipherKey, keySize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return UNEXPECTED_ERROR;
        }

        unsigned int requiredPlaintextSize = 0;
        legacyCipher->Decrypt(ivSize > 0 ? ivPtr : nullptr, ivSize,
                              ciphertextPtr, ciphertextSize,
                              nullptr, 0, &requiredPlaintextSize);

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(requiredPlaintextSize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            if (outputBufferSize)
            {
                *outputBufferSize = static_cast<int>(requiredPlaintextSize);
            }

            return BUFFER_TOO_SMALL;
        }

        unsigned int actualPlaintextSize = 0;
        if (!legacyCipher->Decrypt(ivSize > 0 ? ivPtr : nullptr, ivSize,
                                   ciphertextPtr, ciphertextSize,
                                   outputBuffer, static_cast<unsigned int>(outputBufferCapacity), &actualPlaintextSize))
        {
            SecureZeroMemory(&combinedKey[0], combinedKey.size());
            return INVALID_DATA;
        }

        SecureZeroMemory(&combinedKey[0], combinedKey.size());

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(actualPlaintextSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// Hash (message digest) -- see HashAlgorithm in ProviderTypes.h and the 5-argument constructor.
// Kept in its own section at the end of the file, deliberately separate from the Encrypt*/
// Decrypt* methods above: hashing has no key/password and no ciphertext, so it doesn't share
// their shape, only the same BUFFER_TOO_SMALL capacity-query convention and chunked-progress
// style.
// ================================================================================================

int CCryptoApi::GetHashSize(void) const
{
    try
    {
        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return 0;
        }

        std::unique_ptr<IHashService> hashService = providerFactory->CreateHashService(hashAlgorithm_);
        return hashService ? static_cast<int>(hashService->GetHashSize()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::computeHash(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<IHashService> hashService = providerFactory->CreateHashService(hashAlgorithm_);
        if (!hashService)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int hashSize = hashService->GetHashSize();
        if (hashSize == 0)
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(hashSize))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = static_cast<int>(hashSize);
            }

            return BUFFER_TOO_SMALL;
        }

        if (!hashService->Init())
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned long long totalBytes = static_cast<unsigned long long>(inputBufferSize);
        unsigned long long processedBytes = 0;

        const unsigned int chunkCount = inputBufferSize > 0
            ? static_cast<unsigned int>((static_cast<long long>(inputBufferSize) + BUFFER_CHUNK_SIZE - 1) / BUFFER_CHUNK_SIZE)
            : 0;

        for (unsigned int chunkIndex = 0; chunkIndex < chunkCount; ++chunkIndex)
        {
            const unsigned int offset = chunkIndex * BUFFER_CHUNK_SIZE;
            const unsigned int remainingInput = static_cast<unsigned int>(inputBufferSize) - offset;
            const unsigned int chunkSize = remainingInput < BUFFER_CHUNK_SIZE ? remainingInput : BUFFER_CHUNK_SIZE;

            if (!hashService->Update(inputBuffer + offset, chunkSize))
            {
                return UNEXPECTED_ERROR;
            }

            processedBytes += chunkSize;

            if (onProgress)
            {
                const double percentage = totalBytes > 0
                    ? (static_cast<double>(processedBytes) / static_cast<double>(totalBytes)) * 100.0
                    : 0.0;
                if (!onProgress(processedBytes, totalBytes, percentage, progressUserData))
                {
                    return OPERATION_CANCELLED;
                }
            }
        }

        if (!hashService->Final(outputBuffer, hashSize))
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(hashSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::ComputeHashBuffer(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    return computeHash(inputBuffer, inputBufferSize, outputBufferCapacity, outputBuffer, outputBufferSize, onProgress, progressUserData);
}
// -----------------------------------------------------------------------------

int CCryptoApi::ComputeHashBytes(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    return computeHash(inputBuffer, inputBufferSize, outputBufferCapacity, outputBuffer, outputBufferSize, onProgress, progressUserData);
}
// -----------------------------------------------------------------------------

int CCryptoApi::ComputeHashString(const char* inputString, const int inputStringSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (inputStringSize < 0 || (inputStringSize > 0 && inputString == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        return computeHash(reinterpret_cast<const unsigned char*>(inputString), inputStringSize,
                           outputBufferCapacity, outputBuffer, outputBufferSize, onProgress, progressUserData);
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::ComputeHashFile(const char* inputFilePath, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (inputFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        std::wstring wideInputFilePath;
        if (!convertUtf8PathToWide(inputFilePath, wideInputFilePath))
        {
            return INVALID_ARGUMENT;
        }

        HANDLE rawInputHandle = CreateFileW(wideInputFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawInputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> inputHandle(rawInputHandle, &CloseHandle);

        LARGE_INTEGER inputFileSize;
        inputFileSize.QuadPart = 0;
        GetFileSizeEx(rawInputHandle, &inputFileSize);
        const unsigned long long totalBytes = static_cast<unsigned long long>(inputFileSize.QuadPart);
        unsigned long long processedBytes = 0;

        std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
        if (!providerFactory)
        {
            return UNEXPECTED_ERROR;
        }

        std::unique_ptr<IHashService> hashService = providerFactory->CreateHashService(hashAlgorithm_);
        if (!hashService)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int hashSize = hashService->GetHashSize();
        if (hashSize == 0)
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(hashSize))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = static_cast<int>(hashSize);
            }

            return BUFFER_TOO_SMALL;
        }

        if (!hashService->Init())
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> fileChunk(FILE_CHUNK_SIZE);

        for (;;)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(rawInputHandle, &fileChunk[0], static_cast<DWORD>(fileChunk.size()), &bytesRead, nullptr))
            {
                return FILE_IO_ERROR;
            }

            if (bytesRead == 0)
            {
                break;
            }

            if (!hashService->Update(&fileChunk[0], bytesRead))
            {
                return UNEXPECTED_ERROR;
            }

            processedBytes += bytesRead;

            if (onProgress)
            {
                const double percentage = totalBytes > 0
                    ? (static_cast<double>(processedBytes) / static_cast<double>(totalBytes)) * 100.0
                    : 0.0;
                if (!onProgress(processedBytes, totalBytes, percentage, progressUserData))
                {
                    return OPERATION_CANCELLED;
                }
            }
        }

        if (!hashService->Final(outputBuffer, hashSize))
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(hashSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// Signature (sign/verify) -- see SignatureAlgorithm in ProviderTypes.h and the 6-argument
// constructor. Kept in its own section at the end of the file, deliberately separate from the
// Encrypt*/Decrypt* and Hash methods above: signing has no password and no ciphertext, and unlike
// Hash it caches a key pair across calls (like the RSA/Asymmetric section further up), so it
// doesn't share their shape either.
// ================================================================================================

int CCryptoApi::GenerateSignatureKeyPair(void)
{
    try
    {
        if (!signatureEngine_)
        {
            std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
            if (!providerFactory)
            {
                return UNEXPECTED_ERROR;
            }

            signatureEngine_ = providerFactory->CreateSignatureEngine(signatureAlgorithm_);
            if (!signatureEngine_)
            {
                return UNEXPECTED_ERROR;
            }
        }

        return signatureEngine_->GenerateKeyPair() ? NO_ERROR : UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::GetSignatureSize(void) const
{
    try
    {
        return signatureEngine_ ? static_cast<int>(signatureEngine_->GetSignatureSize()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::SignBuffer(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        if (!signatureEngine_)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int requiredSize = signatureEngine_->GetSignatureSize();
        if (requiredSize == 0)
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(requiredSize))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = static_cast<int>(requiredSize);
            }

            return BUFFER_TOO_SMALL;
        }

        if (!signatureEngine_->Sign(inputBuffer, static_cast<unsigned int>(inputBufferSize),
                                    outputBuffer, static_cast<unsigned int>(outputBufferCapacity)))
        {
            return INVALID_ARGUMENT;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(requiredSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::VerifyBuffer(const unsigned char* inputBuffer, const int inputBufferSize, const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid)
{
    try
    {
        if (isValid)
        {
            *isValid = false;
        }

        if (inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr) ||
            signatureBufferSize < 0 || (signatureBufferSize > 0 && signatureBuffer == nullptr) ||
            isValid == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        if (!signatureEngine_)
        {
            return UNEXPECTED_ERROR;
        }

        *isValid = signatureEngine_->Verify(inputBuffer, static_cast<unsigned int>(inputBufferSize),
                                            signatureBuffer, static_cast<unsigned int>(signatureBufferSize));
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// Key agreement (Diffie-Hellman style) -- see KeyAgreementAlgorithm in ProviderTypes.h and the
// 7-argument/key-agreement-only constructors. Kept in its own section at the end of the file, like
// Signature above: no password, no ciphertext, and unlike Hash it caches a key pair across calls.
// ================================================================================================

int CCryptoApi::GenerateKeyAgreementKeyPair(void)
{
    try
    {
        if (!keyAgreementEngine_)
        {
            std::unique_ptr<ICryptoProviderFactory> providerFactory = CreateProviderFactory(providerKind_);
            if (!providerFactory)
            {
                return UNEXPECTED_ERROR;
            }

            keyAgreementEngine_ = providerFactory->CreateKeyAgreementEngine(keyAgreementAlgorithm_);
            if (!keyAgreementEngine_)
            {
                return UNEXPECTED_ERROR;
            }
        }

        return keyAgreementEngine_->GenerateKeyPair() ? NO_ERROR : UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::GetKeyAgreementPublicKeySize(void) const
{
    try
    {
        return keyAgreementEngine_ ? static_cast<int>(keyAgreementEngine_->GetPublicKeySize()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::GetSharedSecretSize(void) const
{
    try
    {
        return keyAgreementEngine_ ? static_cast<int>(keyAgreementEngine_->GetSharedSecretSize()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::ExportKeyAgreementPublicKey(const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (!keyAgreementEngine_)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int requiredSize = keyAgreementEngine_->GetPublicKeySize();
        if (requiredSize == 0)
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(requiredSize))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = static_cast<int>(requiredSize);
            }

            return BUFFER_TOO_SMALL;
        }

        if (!keyAgreementEngine_->GetPublicKey(outputBuffer, static_cast<unsigned int>(outputBufferCapacity)))
        {
            return INVALID_ARGUMENT;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(requiredSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CCryptoApi::DeriveSharedSecret(const unsigned char* peerPublicKeyBuffer, const int peerPublicKeyBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (peerPublicKeyBufferSize < 0 || (peerPublicKeyBufferSize > 0 && peerPublicKeyBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        if (!keyAgreementEngine_)
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int requiredSize = keyAgreementEngine_->GetSharedSecretSize();
        if (requiredSize == 0)
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(requiredSize))
        {
            if (outputBufferSize)
            {
                *outputBufferSize = static_cast<int>(requiredSize);
            }

            return BUFFER_TOO_SMALL;
        }

        if (!keyAgreementEngine_->DeriveSharedSecret(peerPublicKeyBuffer, static_cast<unsigned int>(peerPublicKeyBufferSize),
                                                     outputBuffer, static_cast<unsigned int>(outputBufferCapacity)))
        {
            return INVALID_ARGUMENT;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = static_cast<int>(requiredSize);
        }

        return NO_ERROR;
    }
    catch (...)
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

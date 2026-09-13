#include "CryptoApi.h"
#include "Utils/Utils.h"
#include "Definitions/Definitions.h"
#include "Providers/MicrosoftProvider/MicrosoftProvider.h"

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

} // namespace

namespace CryptoApiNS
{

CCryptoApi::~CCryptoApi()
{
}
// -----------------------------------------------------------------------------

CCryptoApi::CCryptoApi()
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

        CMicrosoftProvider provider;
        IAeadCipher& cipher = provider;
        IRandomSource& randomSource = provider;

        if (!provider.Initialize())
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int nonceSize = cipher.GetNonceSize();
        const unsigned int tagSize = cipher.GetTagSize();
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

        if (!cipher.SetKey(key, static_cast<unsigned int>(keySize)))
        {
            return INVALID_ARGUMENT;
        }

        unsigned char* noncePtr = outputBuffer;
        unsigned char* ciphertextPtr = outputBuffer + nonceSize;
        unsigned char* tagPtr = ciphertextPtr + inputBufferSize;

        if (!randomSource.GenerateRandomBytes(noncePtr, nonceSize))
        {
            return UNEXPECTED_ERROR;
        }

        if (!cipher.Encrypt(noncePtr, nonceSize,
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

        CMicrosoftProvider provider;
        IAeadCipher& cipher = provider;

        if (!provider.Initialize())
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int nonceSize = cipher.GetNonceSize();
        const unsigned int tagSize = cipher.GetTagSize();
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

        if (!cipher.SetKey(key, static_cast<unsigned int>(keySize)))
        {
            return INVALID_ARGUMENT;
        }

        const unsigned char* noncePtr = inputBuffer;
        const unsigned char* ciphertextPtr = inputBuffer + nonceSize;
        const unsigned char* tagPtr = ciphertextPtr + requiredSize;

        if (!cipher.Decrypt(noncePtr, nonceSize,
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

        CMicrosoftProvider provider;
        IAeadCipher& cipher = provider;
        IRandomSource& randomSource = provider;
        IKeyDerivation& keyDerivation = provider;

        if (!provider.Initialize())
        {
            return UNEXPECTED_ERROR;
        }

        const unsigned int nonceSize = cipher.GetNonceSize();
        const unsigned int tagSize = cipher.GetTagSize();
        const unsigned int keySize = cipher.GetKeySize();
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
        if (!randomSource.GenerateRandomBytes(saltPtr, PASSWORD_SALT_SIZE))
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> key(keySize);
        if (!keyDerivation.DerivePasswordKey(password, static_cast<unsigned int>(passwordSize),
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

        CMicrosoftProvider provider;
        IKeyDerivation& keyDerivation = provider;

        if (!provider.Initialize())
        {
            return UNEXPECTED_ERROR;
        }

        if (static_cast<unsigned int>(inputBufferSize) < PASSWORD_SALT_SIZE)
        {
            return INVALID_DATA;
        }

        const unsigned int keySize = provider.GetKeySize();
        const unsigned int nonceSize = provider.GetNonceSize();
        const unsigned int tagSize = provider.GetTagSize();
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
        if (!keyDerivation.DerivePasswordKey(password, static_cast<unsigned int>(passwordSize),
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

        CMicrosoftProvider provider;
        IAeadCipher& cipher = provider;
        IRandomSource& randomSource = provider;
        IKeyDerivation& keyDerivation = provider;

        if (!provider.Initialize())
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        const unsigned int keySize = cipher.GetKeySize();
        std::vector<unsigned char> salt(PASSWORD_SALT_SIZE);
        if (!randomSource.GenerateRandomBytes(&salt[0], PASSWORD_SALT_SIZE) ||
            !writeFileExact(rawOutputHandle, &salt[0], PASSWORD_SALT_SIZE))
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> key(keySize);
        if (!keyDerivation.DerivePasswordKey(password, static_cast<unsigned int>(passwordSizeValue),
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
        std::vector<unsigned char> encryptedChunk(FILE_CHUNK_SIZE + cipher.GetNonceSize() + cipher.GetTagSize());

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

        CMicrosoftProvider provider;
        IAeadCipher& cipher = provider;
        IKeyDerivation& keyDerivation = provider;

        if (!provider.Initialize())
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return UNEXPECTED_ERROR;
        }

        const unsigned int keySize = cipher.GetKeySize();
        const unsigned int nonceSize = cipher.GetNonceSize();
        const unsigned int tagSize = cipher.GetTagSize();

        std::vector<unsigned char> salt(PASSWORD_SALT_SIZE);
        if (!readFileExact(rawInputHandle, &salt[0], PASSWORD_SALT_SIZE))
        {
            outputHandle.reset();
            deleteFileBestEffort(wideOutputFilePath);
            return INVALID_DATA;
        }

        processedBytes += PASSWORD_SALT_SIZE;

        std::vector<unsigned char> key(keySize);
        if (!keyDerivation.DerivePasswordKey(password, static_cast<unsigned int>(passwordSizeValue),
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

} // namespace CryptoApiNS

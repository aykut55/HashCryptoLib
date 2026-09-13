#include "AeadCipher.h"

namespace CryptoApiNS
{

IAeadCipher::~IAeadCipher()
{
}
// -----------------------------------------------------------------------------

IAeadCipher::IAeadCipher()
{
}
// -----------------------------------------------------------------------------

bool IAeadCipher::EncryptChunked(IRandomSource& randomSource,
                                 const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                                 const unsigned int chunkSize,
                                 unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                                 unsigned int* outputBufferSize,
                                 AeadProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (outputBufferSize == nullptr || chunkSize == 0 ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        const unsigned int nonceSize = GetNonceSize();
        const unsigned int tagSize = GetTagSize();
        const unsigned int recordOverhead = 4u + nonceSize + tagSize;
        const unsigned int chunkCount = inputBufferSize > 0
            ? (inputBufferSize + chunkSize - 1) / chunkSize
            : 0;

        const unsigned long long requiredSizeLL = static_cast<unsigned long long>(inputBufferSize) +
                                                   static_cast<unsigned long long>(chunkCount) *
                                                   static_cast<unsigned long long>(recordOverhead);
        if (requiredSizeLL > 0xFFFFFFFFull)
        {
            return false;
        }

        const unsigned int requiredSize = static_cast<unsigned int>(requiredSizeLL);
        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = requiredSize;
            return false;
        }

        unsigned char* writePtr = outputBuffer;
        const unsigned long long totalBytes = inputBufferSize;
        unsigned long long processedBytes = 0;

        for (unsigned int chunkIndex = 0; chunkIndex < chunkCount; ++chunkIndex)
        {
            const unsigned int offset = chunkIndex * chunkSize;
            const unsigned int remaining = inputBufferSize - offset;
            const unsigned int currentChunkSize = remaining < chunkSize ? remaining : chunkSize;

            unsigned char* noncePtr = writePtr + 4;
            unsigned char* ciphertextPtr = noncePtr + nonceSize;
            unsigned char* tagPtr = ciphertextPtr + currentChunkSize;

            if (!randomSource.GenerateRandomBytes(noncePtr, nonceSize) ||
                !Encrypt(noncePtr, nonceSize, inputBuffer + offset, currentChunkSize, ciphertextPtr, tagPtr, tagSize))
            {
                *outputBufferSize = 0;
                return false;
            }

            writePtr[0] = static_cast<unsigned char>(currentChunkSize);
            writePtr[1] = static_cast<unsigned char>(currentChunkSize >> 8);
            writePtr[2] = static_cast<unsigned char>(currentChunkSize >> 16);
            writePtr[3] = static_cast<unsigned char>(currentChunkSize >> 24);

            writePtr += 4u + nonceSize + currentChunkSize + tagSize;
            processedBytes += currentChunkSize;

            if (onProgress != nullptr)
            {
                const double percentage = totalBytes > 0
                    ? (static_cast<double>(processedBytes) / static_cast<double>(totalBytes)) * 100.0
                    : 0.0;
                if (!onProgress(processedBytes, totalBytes, percentage, progressUserData))
                {
                    *outputBufferSize = 0;
                    return false;
                }
            }
        }

        *outputBufferSize = requiredSize;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool IAeadCipher::DecryptChunked(const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                                 unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                                 unsigned int* outputBufferSize,
                                 AeadProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (outputBufferSize == nullptr || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        const unsigned int nonceSize = GetNonceSize();
        const unsigned int tagSize = GetTagSize();

        // First pass: scan records without decrypting, to compute the required output size.
        unsigned long long requiredSizeLL = 0;
        unsigned int scanPos = 0;
        while (scanPos < inputBufferSize)
        {
            if (inputBufferSize - scanPos < 4u)
            {
                return false;
            }

            const unsigned int chunkPlainSize = static_cast<unsigned int>(inputBuffer[scanPos]) |
                                                (static_cast<unsigned int>(inputBuffer[scanPos + 1]) << 8) |
                                                (static_cast<unsigned int>(inputBuffer[scanPos + 2]) << 16) |
                                                (static_cast<unsigned int>(inputBuffer[scanPos + 3]) << 24);
            scanPos += 4u;

            const unsigned long long recordSize = static_cast<unsigned long long>(chunkPlainSize) +
                                                   static_cast<unsigned long long>(nonceSize) +
                                                   static_cast<unsigned long long>(tagSize);
            if (recordSize > static_cast<unsigned long long>(inputBufferSize - scanPos))
            {
                return false;
            }

            requiredSizeLL += chunkPlainSize;
            scanPos += static_cast<unsigned int>(recordSize);
        }

        if (requiredSizeLL > 0xFFFFFFFFull)
        {
            return false;
        }

        const unsigned int requiredSize = static_cast<unsigned int>(requiredSizeLL);
        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = requiredSize;
            return false;
        }

        // Second pass: decrypt each record in order.
        unsigned int readPos = 0;
        unsigned char* writePtr = outputBuffer;
        const unsigned long long totalBytes = requiredSize;
        unsigned long long processedBytes = 0;

        while (readPos < inputBufferSize)
        {
            const unsigned int chunkPlainSize = static_cast<unsigned int>(inputBuffer[readPos]) |
                                                (static_cast<unsigned int>(inputBuffer[readPos + 1]) << 8) |
                                                (static_cast<unsigned int>(inputBuffer[readPos + 2]) << 16) |
                                                (static_cast<unsigned int>(inputBuffer[readPos + 3]) << 24);
            readPos += 4u;

            const unsigned char* noncePtr = inputBuffer + readPos;
            const unsigned char* ciphertextPtr = noncePtr + nonceSize;
            const unsigned char* tagPtr = ciphertextPtr + chunkPlainSize;

            if (!Decrypt(noncePtr, nonceSize, ciphertextPtr, chunkPlainSize, tagPtr, tagSize, writePtr))
            {
                *outputBufferSize = 0;
                return false;
            }

            readPos += nonceSize + chunkPlainSize + tagSize;
            writePtr += chunkPlainSize;
            processedBytes += chunkPlainSize;

            if (onProgress != nullptr)
            {
                const double percentage = totalBytes > 0
                    ? (static_cast<double>(processedBytes) / static_cast<double>(totalBytes)) * 100.0
                    : 0.0;
                if (!onProgress(processedBytes, totalBytes, percentage, progressUserData))
                {
                    *outputBufferSize = 0;
                    return false;
                }
            }
        }

        *outputBufferSize = requiredSize;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#include "Utils.h"

#include "../CryptoApi.h"
#include "../Definitions/Definitions.h"

#include <cstdlib>
#include <cstring>
#include <string>

namespace
{

int hexNibbleValue(const char character)
{
    if (character >= '0' && character <= '9')
    {
        return character - '0';
    }

    if (character >= 'a' && character <= 'f')
    {
        return character - 'a' + 10;
    }

    if (character >= 'A' && character <= 'F')
    {
        return character - 'A' + 10;
    }

    return -1;
}

int base64CharacterValue(const char character)
{
    if (character >= 'A' && character <= 'Z')
    {
        return character - 'A';
    }

    if (character >= 'a' && character <= 'z')
    {
        return character - 'a' + 26;
    }

    if (character >= '0' && character <= '9')
    {
        return character - '0' + 52;
    }

    if (character == '+')
    {
        return 62;
    }

    if (character == '/')
    {
        return 63;
    }

    return -1;
}

} // anonymous namespace

namespace CryptoApiNS
{

CUtils::~CUtils()
{
}
// -----------------------------------------------------------------------------

CUtils::CUtils()
{
}
// -----------------------------------------------------------------------------

const char* CUtils::FormatBuildDate(void)
{
    try
    {
        static const char* monthNames[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        static const char* monthNumbers[] = {
            "01", "02", "03", "04", "05", "06",
            "07", "08", "09", "10", "11", "12"
        };

        const std::string rawDate = CRYPTOAPI_BUILD_DATE_RAW;
        std::string month = "00";

        for (unsigned int index = 0; index < 12; ++index)
        {
            if (rawDate.compare(0, 3, monthNames[index]) == 0)
            {
                month = monthNumbers[index];
                break;
            }
        }

        std::string formattedDate = rawDate.substr(7, 4) + "." + month + ".";
        formattedDate += rawDate[4] == ' ' ? '0' : rawDate[4];
        formattedDate += rawDate[5];

        static const std::string buildDate = formattedDate;
        return buildDate.c_str();
    }
    catch (...)
    {
        return "";
    }
}
// -----------------------------------------------------------------------------

int CUtils::HexEncode(const unsigned char* inputBuffer, const int inputBufferSize, const bool upperCase, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
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

        const int requiredSize = inputBufferSize * 2;

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        static const char lowerCaseDigits[] = "0123456789abcdef";
        static const char upperCaseDigits[] = "0123456789ABCDEF";
        const char* digits = upperCase ? upperCaseDigits : lowerCaseDigits;

        for (int index = 0; index < inputBufferSize; ++index)
        {
            const unsigned char byteValue = inputBuffer[index];
            outputBuffer[index * 2]     = digits[(byteValue >> 4) & 0x0F];
            outputBuffer[index * 2 + 1] = digits[byteValue & 0x0F];
        }

        if (outputBufferSize)
        {
            *outputBufferSize = requiredSize;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CUtils::HexDecode(const char* inputString, const int inputStringSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (inputStringSize < 0 || (inputStringSize > 0 && inputString == nullptr) || (inputStringSize % 2) != 0)
        {
            return INVALID_ARGUMENT;
        }

        const int requiredSize = inputStringSize / 2;

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        for (int index = 0; index < requiredSize; ++index)
        {
            const int highNibble = hexNibbleValue(inputString[index * 2]);
            const int lowNibble = hexNibbleValue(inputString[index * 2 + 1]);

            if (highNibble < 0 || lowNibble < 0)
            {
                return INVALID_DATA;
            }

            outputBuffer[index] = static_cast<unsigned char>((highNibble << 4) | lowNibble);
        }

        if (outputBufferSize)
        {
            *outputBufferSize = requiredSize;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CUtils::Base64Encode(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
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

        const int requiredSize = ((inputBufferSize + 2) / 3) * 4;

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        static const char base64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        int outputIndex = 0;
        int index = 0;
        for (; index + 2 < inputBufferSize; index += 3)
        {
            const unsigned int chunk = (static_cast<unsigned int>(inputBuffer[index]) << 16) |
                                       (static_cast<unsigned int>(inputBuffer[index + 1]) << 8) |
                                        static_cast<unsigned int>(inputBuffer[index + 2]);

            outputBuffer[outputIndex++] = base64Alphabet[(chunk >> 18) & 0x3F];
            outputBuffer[outputIndex++] = base64Alphabet[(chunk >> 12) & 0x3F];
            outputBuffer[outputIndex++] = base64Alphabet[(chunk >> 6) & 0x3F];
            outputBuffer[outputIndex++] = base64Alphabet[chunk & 0x3F];
        }

        const int remaining = inputBufferSize - index;
        if (remaining == 1)
        {
            const unsigned int chunk = static_cast<unsigned int>(inputBuffer[index]) << 16;

            outputBuffer[outputIndex++] = base64Alphabet[(chunk >> 18) & 0x3F];
            outputBuffer[outputIndex++] = base64Alphabet[(chunk >> 12) & 0x3F];
            outputBuffer[outputIndex++] = '=';
            outputBuffer[outputIndex++] = '=';
        }
        else if (remaining == 2)
        {
            const unsigned int chunk = (static_cast<unsigned int>(inputBuffer[index]) << 16) |
                                       (static_cast<unsigned int>(inputBuffer[index + 1]) << 8);

            outputBuffer[outputIndex++] = base64Alphabet[(chunk >> 18) & 0x3F];
            outputBuffer[outputIndex++] = base64Alphabet[(chunk >> 12) & 0x3F];
            outputBuffer[outputIndex++] = base64Alphabet[(chunk >> 6) & 0x3F];
            outputBuffer[outputIndex++] = '=';
        }

        if (outputBufferSize)
        {
            *outputBufferSize = outputIndex;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CUtils::Base64Decode(const char* inputString, const int inputStringSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (inputStringSize < 0 || (inputStringSize > 0 && inputString == nullptr) || (inputStringSize % 4) != 0)
        {
            return INVALID_ARGUMENT;
        }

        int paddingCount = 0;
        if (inputStringSize >= 1 && inputString[inputStringSize - 1] == '=')
        {
            ++paddingCount;
        }
        if (inputStringSize >= 2 && inputString[inputStringSize - 2] == '=')
        {
            ++paddingCount;
        }

        const int requiredSize = inputStringSize == 0 ? 0 : (inputStringSize / 4) * 3 - paddingCount;

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        int outputIndex = 0;
        for (int index = 0; index < inputStringSize; index += 4)
        {
            const char c0 = inputString[index];
            const char c1 = inputString[index + 1];
            const char c2 = inputString[index + 2];
            const char c3 = inputString[index + 3];

            const int v0 = base64CharacterValue(c0);
            const int v1 = base64CharacterValue(c1);

            if (v0 < 0 || v1 < 0)
            {
                return INVALID_DATA;
            }

            outputBuffer[outputIndex++] = static_cast<unsigned char>((v0 << 2) | (v1 >> 4));

            if (c2 != '=')
            {
                const int v2 = base64CharacterValue(c2);
                if (v2 < 0)
                {
                    return INVALID_DATA;
                }

                outputBuffer[outputIndex++] = static_cast<unsigned char>(((v1 & 0x0F) << 4) | (v2 >> 2));

                if (c3 != '=')
                {
                    const int v3 = base64CharacterValue(c3);
                    if (v3 < 0)
                    {
                        return INVALID_DATA;
                    }

                    outputBuffer[outputIndex++] = static_cast<unsigned char>(((v2 & 0x03) << 6) | v3);
                }
            }
        }

        if (outputBufferSize)
        {
            *outputBufferSize = outputIndex;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CUtils::Pad(const PaddingScheme scheme, const unsigned int blockSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (blockSize == 0 || blockSize > 255)
        {
            return INVALID_ARGUMENT;
        }

        if (inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        const unsigned int remainder = static_cast<unsigned int>(inputBufferSize) % blockSize;

        int padLength = 0;
        switch (scheme)
        {
            case PADDING_NONE:
                if (remainder != 0)
                {
                    return INVALID_ARGUMENT;
                }
                padLength = 0;
                break;

            case PADDING_ZERO:
                padLength = remainder == 0 ? 0 : static_cast<int>(blockSize - remainder);
                break;

            case PADDING_PKCS7:
            case PADDING_PKCS5:
            case PADDING_ANSI_X923:
            case PADDING_ISO_10126:
            case PADDING_ISO_97971:
                padLength = static_cast<int>(blockSize - remainder);
                break;

            default:
                return INVALID_ARGUMENT;
        }

        const int requiredSize = inputBufferSize + padLength;

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = requiredSize;
            }

            return BUFFER_TOO_SMALL;
        }

        if (inputBufferSize > 0)
        {
            std::memcpy(outputBuffer, inputBuffer, static_cast<std::size_t>(inputBufferSize));
        }

        unsigned char* padStart = outputBuffer + inputBufferSize;

        switch (scheme)
        {
            case PADDING_NONE:
                break;

            case PADDING_ZERO:
                if (padLength > 0)
                {
                    std::memset(padStart, 0x00, static_cast<std::size_t>(padLength));
                }
                break;

            case PADDING_PKCS7:
            case PADDING_PKCS5:
                std::memset(padStart, static_cast<unsigned char>(padLength), static_cast<std::size_t>(padLength));
                break;

            case PADDING_ANSI_X923:
                if (padLength > 1)
                {
                    std::memset(padStart, 0x00, static_cast<std::size_t>(padLength - 1));
                }
                padStart[padLength - 1] = static_cast<unsigned char>(padLength);
                break;

            case PADDING_ISO_10126:
                for (int index = 0; index < padLength - 1; ++index)
                {
                    padStart[index] = static_cast<unsigned char>(std::rand() & 0xFF);
                }
                padStart[padLength - 1] = static_cast<unsigned char>(padLength);
                break;

            case PADDING_ISO_97971:
                padStart[0] = 0x80;
                if (padLength > 1)
                {
                    std::memset(padStart + 1, 0x00, static_cast<std::size_t>(padLength - 1));
                }
                break;

            default:
                return INVALID_ARGUMENT;
        }

        if (outputBufferSize)
        {
            *outputBufferSize = requiredSize;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CUtils::Unpad(const PaddingScheme scheme, const unsigned int blockSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (outputBufferSize)
        {
            *outputBufferSize = 0;
        }

        if (blockSize == 0 || blockSize > 255)
        {
            return INVALID_ARGUMENT;
        }

        if (inputBufferSize <= 0 || inputBuffer == nullptr || (static_cast<unsigned int>(inputBufferSize) % blockSize) != 0)
        {
            return INVALID_ARGUMENT;
        }

        int dataLength = inputBufferSize;

        switch (scheme)
        {
            case PADDING_NONE:
                break;

            case PADDING_ZERO:
            {
                int index = inputBufferSize;
                while (index > 0 && inputBuffer[index - 1] == 0x00)
                {
                    --index;
                }
                dataLength = index;
                break;
            }

            case PADDING_PKCS7:
            case PADDING_PKCS5:
            {
                const unsigned char padValue = inputBuffer[inputBufferSize - 1];
                if (padValue == 0 || padValue > blockSize || static_cast<int>(padValue) > inputBufferSize)
                {
                    return INVALID_DATA;
                }

                for (int index = 0; index < padValue; ++index)
                {
                    if (inputBuffer[inputBufferSize - 1 - index] != padValue)
                    {
                        return INVALID_DATA;
                    }
                }

                dataLength = inputBufferSize - padValue;
                break;
            }

            case PADDING_ANSI_X923:
            {
                const unsigned char padValue = inputBuffer[inputBufferSize - 1];
                if (padValue == 0 || padValue > blockSize || static_cast<int>(padValue) > inputBufferSize)
                {
                    return INVALID_DATA;
                }

                for (int index = 1; index < padValue; ++index)
                {
                    if (inputBuffer[inputBufferSize - 1 - index] != 0x00)
                    {
                        return INVALID_DATA;
                    }
                }

                dataLength = inputBufferSize - padValue;
                break;
            }

            case PADDING_ISO_10126:
            {
                const unsigned char padValue = inputBuffer[inputBufferSize - 1];
                if (padValue == 0 || padValue > blockSize || static_cast<int>(padValue) > inputBufferSize)
                {
                    return INVALID_DATA;
                }

                dataLength = inputBufferSize - padValue;
                break;
            }

            case PADDING_ISO_97971:
            {
                int index = inputBufferSize;
                while (index > 0 && inputBuffer[index - 1] == 0x00)
                {
                    --index;
                }

                if (index == 0 || inputBuffer[index - 1] != 0x80)
                {
                    return INVALID_DATA;
                }

                dataLength = index - 1;
                break;
            }

            default:
                return INVALID_ARGUMENT;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < dataLength)
        {
            if (outputBufferSize)
            {
                *outputBufferSize = dataLength;
            }

            return BUFFER_TOO_SMALL;
        }

        if (dataLength > 0)
        {
            std::memcpy(outputBuffer, inputBuffer, static_cast<std::size_t>(dataLength));
        }

        if (outputBufferSize)
        {
            *outputBufferSize = dataLength;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

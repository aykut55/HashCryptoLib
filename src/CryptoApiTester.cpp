#include "CryptoApiTester.h"

#include "CryptoApi.h"
#include "Defiinions/Definitions.h"

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

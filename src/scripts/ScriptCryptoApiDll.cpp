#include "ScriptCryptoApiDll.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

namespace
{

// Bridges ICryptoApi's raw C-ABI ProgressCallback (a plain __cdecl function pointer -- it cannot
// capture state itself) to a script-supplied ScriptProgressCallback -- same technique and same
// reasoning as ScriptCryptoApi.cpp's own scriptProgressTrampoline (see that one's comment for the
// full explanation of the userData lifetime and why a thrown script-side exception is treated as
// "stop"), duplicated here rather than shared because the two trampolines bridge to different
// concrete ProgressCallback-taking methods (ICryptoApi's virtual one here vs. CCryptoApi's own),
// matching this repo's established parallel/non-DRY convention for near-identical helpers that
// belong to genuinely separate classes.
bool __cdecl scriptProgressTrampoline(const unsigned long long currentByte, const unsigned long long totalByte, const double percentage, void* userData)
{
    try
    {
        const ScriptProgressCallback* callback = static_cast<const ScriptProgressCallback*>(userData);
        if (callback && *callback)
        {
            return (*callback)(currentByte, totalByte, percentage);
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace

std::vector<unsigned char> CScriptCryptoApiDll::callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const
{
    try
    {
        int requiredSize = 0;
        int rc = fn(0, nullptr, &requiredSize);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": size query failed");
        }

        std::vector<unsigned char> output(static_cast<size_t>(requiredSize));
        rc = fn(requiredSize, output.empty() ? nullptr : &output[0], &requiredSize);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": call failed");
        }

        output.resize(static_cast<size_t>(requiredSize));
        return output;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string(methodName) + ": " + ex.what());
    }
}
// -----------------------------------------------------------------------------

CScriptCryptoApiDll::~CScriptCryptoApiDll()
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApiDll::CScriptCryptoApiDll(ICryptoApi* api) : api_(api)
{
}
// -----------------------------------------------------------------------------

std::string CScriptCryptoApiDll::GetVersion(void) const
{
    try
    {
        return api_->GetVersion();
    }
    catch (...)
    {
        return std::string();
    }
}
// -----------------------------------------------------------------------------

int CScriptCryptoApiDll::GetHashSize(void) const
{
    try
    {
        return api_->GetHashSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApiDll::ComputeHashString(const std::string& input)
{
    return callBinaryOutput("ComputeHashString", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_->ComputeHashString(input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApiDll::callVoid(const char* methodName, const std::function<int(void)>& fn) const
{
    try
    {
        int rc = fn();
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": call failed");
        }
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string(methodName) + ": " + ex.what());
    }
}
// -----------------------------------------------------------------------------

void CScriptCryptoApiDll::EncryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath, const ScriptProgressCallback& onProgress)
{
    callVoid("EncryptFile", [this, &password, &inputFilePath, &outputFilePath, &onProgress]()
    {
        ScriptProgressCallback callback = onProgress;
        return api_->EncryptFile(password.c_str(), inputFilePath.c_str(), outputFilePath.c_str(), scriptProgressTrampoline, &callback);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApiDll::DecryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath, const ScriptProgressCallback& onProgress)
{
    callVoid("DecryptFile", [this, &password, &inputFilePath, &outputFilePath, &onProgress]()
    {
        ScriptProgressCallback callback = onProgress;
        return api_->DecryptFile(password.c_str(), inputFilePath.c_str(), outputFilePath.c_str(), scriptProgressTrampoline, &callback);
    });
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#include "ScriptCryptoApiDll.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

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

} // namespace CryptoApiNS

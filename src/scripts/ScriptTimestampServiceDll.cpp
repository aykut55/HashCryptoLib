#include "ScriptTimestampServiceDll.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::vector<unsigned char> CScriptTimestampServiceDll::callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const
{
    try
    {
        int requiredSize = 0;
        int rc = fn(0, nullptr, &requiredSize);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": size query failed");
        }

        // Bounded retry: the underlying call can be non-idempotent (fresh randomness -- e.g. a
        // random serial number, a new signature, an RFC 3161 nonce -- each time it runs), so the
        // size this query just reported is not guaranteed to still fit the NEXT (real) invocation
        // of the same method. Re-querying and retrying keeps this self-correcting instead of
        // surfacing a spurious BUFFER_TOO_SMALL as a generic "call failed".
        std::vector<unsigned char> output;
        for (int attempt = 0; attempt < 5; ++attempt)
        {
            output.assign(static_cast<size_t>(requiredSize), 0);
            rc = fn(requiredSize, output.empty() ? nullptr : &output[0], &requiredSize);
            if (rc != BUFFER_TOO_SMALL)
            {
                break;
            }
        }
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

std::string CScriptTimestampServiceDll::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
{
    try
    {
        int requiredSize = 0;
        int rc = fn(0, nullptr, &requiredSize);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": size query failed");
        }

        // (No retry loop needed here -- every callTextOutput caller inspects EXISTING, already-
        // generated data, so its output length is deterministic given the same input.)
        std::vector<char> output(static_cast<size_t>(requiredSize));
        rc = fn(requiredSize, output.empty() ? nullptr : &output[0], &requiredSize);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": call failed");
        }

        return std::string(output.empty() ? "" : &output[0], static_cast<size_t>(requiredSize));
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

CScriptTimestampServiceDll::~CScriptTimestampServiceDll()
{
}
// -----------------------------------------------------------------------------

CScriptTimestampServiceDll::CScriptTimestampServiceDll(ITimestampService* service) : service_(service)
{
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptTimestampServiceDll::CreateTimestampRequest(const std::vector<unsigned char>& digest, const int digestAlgorithm)
{
    return callBinaryOutput("CreateTimestampRequest", [this, &digest, digestAlgorithm](int capacity, unsigned char* buffer, int* actualSize)
    {
        return service_->CreateTimestampRequest( digest.empty() ? nullptr : &digest[0], static_cast<int>(digest.size()),
                                                 static_cast<TimestampDigestAlgorithm>(digestAlgorithm), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptTimestampServiceDll::RequestTimestampFromTsa( const std::string& tsaUrl, const std::vector<unsigned char>& requestDer,
                                                                                const int timeoutMilliseconds)
{
    return callBinaryOutput("RequestTimestampFromTsa", [this, &tsaUrl, &requestDer, timeoutMilliseconds](int capacity, unsigned char* buffer, int* actualSize)
    {
        return service_->RequestTimestampFromTsa( tsaUrl.data(), static_cast<int>(tsaUrl.size()),
                                                  requestDer.empty() ? nullptr : &requestDer[0], static_cast<int>(requestDer.size()),
                                                  timeoutMilliseconds, capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptTimestampServiceDll::GetTimestampInfoText(const std::vector<unsigned char>& responseDer) const
{
    return callTextOutput("GetTimestampInfoText", [this, &responseDer](int capacity, char* buffer, int* actualSize)
    {
        return service_->GetTimestampInfoText(responseDer.empty() ? nullptr : &responseDer[0], static_cast<int>(responseDer.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

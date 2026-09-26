#include "ScriptCmsServiceDll.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::vector<unsigned char> CScriptCmsServiceDll::callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const
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

CScriptCmsServiceDll::~CScriptCmsServiceDll()
{
}
// -----------------------------------------------------------------------------

CScriptCmsServiceDll::CScriptCmsServiceDll(ICmsService* service) : service_(service)
{
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCmsServiceDll::SignDetached( const std::vector<unsigned char>& data, const std::vector<unsigned char>& signerCertDer,
                                                                const std::string& signerPrivateKeyPem, const int digestAlgorithm)
{
    return callBinaryOutput("SignDetached", [this, &data, &signerCertDer, &signerPrivateKeyPem, digestAlgorithm](int capacity, unsigned char* buffer, int* actualSize)
    {
        return service_->SignDetached( data.empty() ? nullptr : &data[0], static_cast<int>(data.size()),
                                       signerCertDer.empty() ? nullptr : &signerCertDer[0], static_cast<int>(signerCertDer.size()),
                                       signerPrivateKeyPem.data(), static_cast<int>(signerPrivateKeyPem.size()),
                                       static_cast<CmsDigestAlgorithm>(digestAlgorithm), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

int CScriptCmsServiceDll::VerifyDetached(const std::vector<unsigned char>& data, const std::vector<unsigned char>& cmsDer)
{
    try
    {
        int verificationResult = 0;
        int rc = service_->VerifyDetached( data.empty() ? nullptr : &data[0], static_cast<int>(data.size()),
                                          cmsDer.empty() ? nullptr : &cmsDer[0], static_cast<int>(cmsDer.size()),
                                          nullptr, 0, &verificationResult);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "VerifyDetached: call failed");
        }
        return verificationResult;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("VerifyDetached: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

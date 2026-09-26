#include "ScriptCertificateManagerDll.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::string CScriptCertificateManagerDll::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
{
    try
    {
        int requiredSize = 0;
        int rc = fn(0, nullptr, &requiredSize);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": size query failed");
        }

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

CScriptCertificateManagerDll::~CScriptCertificateManagerDll()
{
}
// -----------------------------------------------------------------------------

CScriptCertificateManagerDll::CScriptCertificateManagerDll(ICertificateManager* manager) : manager_(manager)
{
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCertificateManagerDll::CreateSelfSignedCertificate( const std::string& subjectCommonName, const int keyAlgorithm,
                                                                                      const int validityDays, const int digestAlgorithm)
{
    try
    {
        int certRequiredSize = 0;
        int keyRequiredSize = 0;
        int rc = manager_->CreateSelfSignedCertificate( subjectCommonName.data(), static_cast<int>(subjectCommonName.size()), nullptr, 0,
                                                        static_cast<CertificateKeyAlgorithm>(keyAlgorithm), validityDays, 0, 0,
                                                        static_cast<CertificateDigestAlgorithm>(digestAlgorithm),
                                                        0, nullptr, &certRequiredSize, 0, nullptr, &keyRequiredSize);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "CreateSelfSignedCertificate: size query failed");
        }

        std::vector<unsigned char> certDer(static_cast<size_t>(certRequiredSize));
        std::vector<char> keyPem(static_cast<size_t>(keyRequiredSize));
        rc = manager_->CreateSelfSignedCertificate( subjectCommonName.data(), static_cast<int>(subjectCommonName.size()), nullptr, 0,
                                                    static_cast<CertificateKeyAlgorithm>(keyAlgorithm), validityDays, 0, 0,
                                                    static_cast<CertificateDigestAlgorithm>(digestAlgorithm),
                                                    certRequiredSize, certDer.empty() ? nullptr : &certDer[0], &certRequiredSize,
                                                    keyRequiredSize, keyPem.empty() ? nullptr : &keyPem[0], &keyRequiredSize);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "CreateSelfSignedCertificate: call failed");
        }

        certDer.resize(static_cast<size_t>(certRequiredSize));
        lastPrivateKeyPem_.assign(keyPem.empty() ? "" : &keyPem[0], static_cast<size_t>(keyRequiredSize));
        return certDer;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("CreateSelfSignedCertificate: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

std::string CScriptCertificateManagerDll::GetLastPrivateKeyPem(void) const
{
    return lastPrivateKeyPem_;
}
// -----------------------------------------------------------------------------

std::string CScriptCertificateManagerDll::GetCertificateInfoText(const std::vector<unsigned char>& certDer) const
{
    return callTextOutput("GetCertificateInfoText", [this, &certDer](int capacity, char* buffer, int* actualSize)
    {
        return manager_->GetCertificateInfoText(certDer.empty() ? nullptr : &certDer[0], static_cast<int>(certDer.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

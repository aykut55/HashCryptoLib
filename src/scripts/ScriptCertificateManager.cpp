#include "ScriptCertificateManager.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::vector<unsigned char> CScriptCertificateManager::callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const
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

std::string CScriptCertificateManager::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
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

void CScriptCertificateManager::callVoid(const char* methodName, const std::function<int(void)>& fn) const
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

CScriptCertificateManager::~CScriptCertificateManager()
{
}
// -----------------------------------------------------------------------------

CScriptCertificateManager::CScriptCertificateManager() : engine_(), lastRevocationStatus_(REVOCATION_STATUS_NOT_CHECKED)
{
}
// -----------------------------------------------------------------------------

std::string CScriptCertificateManager::GetCertificateInfoText(const std::vector<unsigned char>& certDer) const
{
    return callTextOutput("GetCertificateInfoText", [this, &certDer](int capacity, char* buffer, int* actualSize)
    {
        return engine_.GetCertificateInfoText(certDer.empty() ? nullptr : &certDer[0], static_cast<int>(certDer.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptCertificateManager::ConvertCertificateDerToPem(const std::vector<unsigned char>& derBuffer) const
{
    return callTextOutput("ConvertCertificateDerToPem", [this, &derBuffer](int capacity, char* buffer, int* actualSize)
    {
        return engine_.ConvertCertificateDerToPem(derBuffer.empty() ? nullptr : &derBuffer[0], static_cast<int>(derBuffer.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCertificateManager::ConvertCertificatePemToDer(const std::string& pemString) const
{
    return callBinaryOutput("ConvertCertificatePemToDer", [this, &pemString](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engine_.ConvertCertificatePemToDer(pemString.data(), static_cast<int>(pemString.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCertificateManager::CreateSelfSignedCertificate( const std::string& subjectCommonName, const std::string& sanDnsNamesCsv,
                                                                                    const int keyAlgorithm, const int validityDays,
                                                                                    const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                                                                    const int digestAlgorithm)
{
    try
    {
        int certRequiredSize = 0;
        int keyRequiredSize = 0;
        int rc = engine_.CreateSelfSignedCertificate( subjectCommonName.data(), static_cast<int>(subjectCommonName.size()),
                                                      sanDnsNamesCsv.data(), static_cast<int>(sanDnsNamesCsv.size()),
                                                      static_cast<CertificateKeyAlgorithm>(keyAlgorithm), validityDays,
                                                      keyUsageFlags, extendedKeyUsageFlags, static_cast<CertificateDigestAlgorithm>(digestAlgorithm),
                                                      0, nullptr, &certRequiredSize, 0, nullptr, &keyRequiredSize);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "CreateSelfSignedCertificate: size query failed");
        }

        std::vector<unsigned char> certDer(static_cast<size_t>(certRequiredSize));
        std::vector<char> keyPem(static_cast<size_t>(keyRequiredSize));
        rc = engine_.CreateSelfSignedCertificate( subjectCommonName.data(), static_cast<int>(subjectCommonName.size()),
                                                  sanDnsNamesCsv.data(), static_cast<int>(sanDnsNamesCsv.size()),
                                                  static_cast<CertificateKeyAlgorithm>(keyAlgorithm), validityDays,
                                                  keyUsageFlags, extendedKeyUsageFlags, static_cast<CertificateDigestAlgorithm>(digestAlgorithm),
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

std::vector<unsigned char> CScriptCertificateManager::CreateCertificateRequest( const std::string& subjectCommonName, const std::string& sanDnsNamesCsv,
                                                                                const int keyAlgorithm, const int digestAlgorithm)
{
    try
    {
        int csrRequiredSize = 0;
        int keyRequiredSize = 0;
        int rc = engine_.CreateCertificateRequest( subjectCommonName.data(), static_cast<int>(subjectCommonName.size()),
                                                   sanDnsNamesCsv.data(), static_cast<int>(sanDnsNamesCsv.size()),
                                                   static_cast<CertificateKeyAlgorithm>(keyAlgorithm), static_cast<CertificateDigestAlgorithm>(digestAlgorithm),
                                                   0, nullptr, &csrRequiredSize, 0, nullptr, &keyRequiredSize);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "CreateCertificateRequest: size query failed");
        }

        std::vector<unsigned char> csrDer(static_cast<size_t>(csrRequiredSize));
        std::vector<char> keyPem(static_cast<size_t>(keyRequiredSize));
        rc = engine_.CreateCertificateRequest( subjectCommonName.data(), static_cast<int>(subjectCommonName.size()),
                                               sanDnsNamesCsv.data(), static_cast<int>(sanDnsNamesCsv.size()),
                                               static_cast<CertificateKeyAlgorithm>(keyAlgorithm), static_cast<CertificateDigestAlgorithm>(digestAlgorithm),
                                               csrRequiredSize, csrDer.empty() ? nullptr : &csrDer[0], &csrRequiredSize,
                                               keyRequiredSize, keyPem.empty() ? nullptr : &keyPem[0], &keyRequiredSize);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "CreateCertificateRequest: call failed");
        }

        csrDer.resize(static_cast<size_t>(csrRequiredSize));
        lastPrivateKeyPem_.assign(keyPem.empty() ? "" : &keyPem[0], static_cast<size_t>(keyRequiredSize));
        return csrDer;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("CreateCertificateRequest: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

std::string CScriptCertificateManager::GetLastPrivateKeyPem(void) const
{
    return lastPrivateKeyPem_;
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCertificateManager::IssueCertificateFromRequest( const std::vector<unsigned char>& csrDer, const std::vector<unsigned char>& caCertDer,
                                                                                   const std::string& caPrivateKeyPem, const int validityDays,
                                                                                   const unsigned int keyUsageFlags, const unsigned int extendedKeyUsageFlags,
                                                                                   const int digestAlgorithm)
{
    return callBinaryOutput("IssueCertificateFromRequest", [this, &csrDer, &caCertDer, &caPrivateKeyPem, validityDays, keyUsageFlags, extendedKeyUsageFlags, digestAlgorithm]
                            (int capacity, unsigned char* buffer, int* actualSize)
    {
        return engine_.IssueCertificateFromRequest( csrDer.empty() ? nullptr : &csrDer[0], static_cast<int>(csrDer.size()),
                                                    caCertDer.empty() ? nullptr : &caCertDer[0], static_cast<int>(caCertDer.size()),
                                                    caPrivateKeyPem.data(), static_cast<int>(caPrivateKeyPem.size()),
                                                    validityDays, keyUsageFlags, extendedKeyUsageFlags, static_cast<CertificateDigestAlgorithm>(digestAlgorithm),
                                                    capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

void CScriptCertificateManager::AddIntermediateCertificateForChainValidation(const std::vector<unsigned char>& certDer)
{
    callVoid("AddIntermediateCertificateForChainValidation", [this, &certDer]()
    {
        return engine_.AddIntermediateCertificateForChainValidation(certDer.empty() ? nullptr : &certDer[0], static_cast<int>(certDer.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptCertificateManager::ClearIntermediateCertificatesForChainValidation(void)
{
    callVoid("ClearIntermediateCertificatesForChainValidation", [this]()
    {
        return engine_.ClearIntermediateCertificatesForChainValidation();
    });
}
// -----------------------------------------------------------------------------

int CScriptCertificateManager::ValidateChain(const std::vector<unsigned char>& leafCertDer, const int revocationMode, const int revocationNetworkMode)
{
    try
    {
        int trustResult = 0;
        int revocationStatus = 0;
        int rc = engine_.ValidateChain( leafCertDer.empty() ? nullptr : &leafCertDer[0], static_cast<int>(leafCertDer.size()),
                                       static_cast<RevocationMode>(revocationMode), static_cast<RevocationNetworkMode>(revocationNetworkMode),
                                       &trustResult, &revocationStatus);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "ValidateChain: call failed");
        }

        lastRevocationStatus_ = revocationStatus;
        return trustResult;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("ValidateChain: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

int CScriptCertificateManager::GetLastRevocationStatus(void) const
{
    return lastRevocationStatus_;
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

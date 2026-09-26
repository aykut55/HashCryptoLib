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

std::string CScriptCryptoApiDll::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
{
    try
    {
        int requiredSize = 0;
        int rc = fn(0, nullptr, &requiredSize);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": size query failed");
        }

        // (No retry loop needed here -- DecryptString inspects EXISTING ciphertext, so its output
        // length is deterministic given the same input.)
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

std::vector<unsigned char> CScriptCryptoApiDll::EncryptString(const std::string& password, const std::string& input)
{
    return callBinaryOutput("EncryptString", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_->EncryptString(password.data(), static_cast<int>(password.size()), input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptCryptoApiDll::DecryptString(const std::string& password, const std::vector<unsigned char>& input)
{
    return callTextOutput("DecryptString", [this, &password, &input](int capacity, char* buffer, int* actualSize)
    {
        return api_->DecryptString(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApiDll::GenerateAsymmetricKeyPair(void)
{
    callVoid("GenerateAsymmetricKeyPair", [this]()
    {
        return api_->GenerateAsymmetricKeyPair();
    });
}
// -----------------------------------------------------------------------------

int CScriptCryptoApiDll::GetAsymmetricCiphertextSize(void) const
{
    try
    {
        return api_->GetAsymmetricCiphertextSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApiDll::EncryptWithPublicKey(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("EncryptWithPublicKey", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_->EncryptWithPublicKey(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApiDll::DecryptWithPrivateKey(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("DecryptWithPrivateKey", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_->DecryptWithPrivateKey(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApiDll::GenerateSignatureKeyPair(void)
{
    callVoid("GenerateSignatureKeyPair", [this]()
    {
        return api_->GenerateSignatureKeyPair();
    });
}
// -----------------------------------------------------------------------------

int CScriptCryptoApiDll::GetSignatureSize(void) const
{
    try
    {
        return api_->GetSignatureSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApiDll::SignBuffer(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("SignBuffer", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_->SignBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

bool CScriptCryptoApiDll::VerifyBuffer(const std::vector<unsigned char>& input, const std::vector<unsigned char>& signature)
{
    try
    {
        bool isValid = false;
        int rc = api_->VerifyBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), signature.empty() ? nullptr : &signature[0], static_cast<int>(signature.size()), &isValid);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "VerifyBuffer: verification could not run");
        }

        return isValid;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("VerifyBuffer: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

void CScriptCryptoApiDll::GenerateKeyAgreementKeyPair(void)
{
    callVoid("GenerateKeyAgreementKeyPair", [this]()
    {
        return api_->GenerateKeyAgreementKeyPair();
    });
}
// -----------------------------------------------------------------------------

int CScriptCryptoApiDll::GetSharedSecretSize(void) const
{
    try
    {
        return api_->GetSharedSecretSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApiDll::ExportKeyAgreementPublicKey(void)
{
    return callBinaryOutput("ExportKeyAgreementPublicKey", [this](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_->ExportKeyAgreementPublicKey(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApiDll::DeriveSharedSecret(const std::vector<unsigned char>& peerPublicKey)
{
    return callBinaryOutput("DeriveSharedSecret", [this, &peerPublicKey](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_->DeriveSharedSecret(peerPublicKey.empty() ? nullptr : &peerPublicKey[0], static_cast<int>(peerPublicKey.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApiDll::GenerateRandomBytes(const int outputSize)
{
    try
    {
        std::vector<unsigned char> output(static_cast<size_t>(outputSize));
        int rc = api_->GenerateRandomBytes(output.empty() ? nullptr : &output[0], outputSize);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "GenerateRandomBytes: call failed");
        }

        return output;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("GenerateRandomBytes: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

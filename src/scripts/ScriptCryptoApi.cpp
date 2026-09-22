#include "ScriptCryptoApi.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

namespace
{

// Bridges CCryptoApi's raw C-ABI ProgressCallback (a plain __cdecl function pointer -- it cannot
// capture state itself) to a script-supplied ScriptProgressCallback: userData points at the actual
// std::function for the duration of the EncryptFile/DecryptFile call (see those two overloads
// below, where a local copy of the caller's ScriptProgressCallback is kept alive on the stack for
// exactly that duration), and this trampoline just dereferences it and calls through. A thrown
// script-side exception must never cross back into CCryptoApi's own C-ABI boundary (Rules.md), so
// it is caught here; treated as "stop" (false) rather than silently swallowed and continued, since
// a script callback that just threw is presumably no longer in a state fit to keep reporting
// progress -- the operation then returns OPERATION_CANCELLED, which callVoid below turns into a
// CScriptException the caller actually sees (not a silently-completed operation the script thinks
// failed).
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

std::vector<unsigned char> CScriptCryptoApi::callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const
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

std::string CScriptCryptoApi::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
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

void CScriptCryptoApi::callVoid(const char* methodName, const std::function<int(void)>& fn) const
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

CScriptCryptoApi::~CScriptCryptoApi()
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi() : api_()
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm) : api_(providerKind, aeadAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const HashAlgorithm hashAlgorithm) : api_(providerKind, hashAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const AsymmetricAlgorithm asymmetricAlgorithm) : api_(providerKind, asymmetricAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const LegacySymmetricAlgorithm legacyAlgorithm) : api_(providerKind, legacyAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const SignatureAlgorithm signatureAlgorithm) : api_(providerKind, signatureAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const KeyAgreementAlgorithm keyAgreementAlgorithm) : api_(providerKind, keyAgreementAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm) : api_(providerKind, aeadAlgorithm, asymmetricAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm) : api_(providerKind, aeadAlgorithm, asymmetricAlgorithm, legacyAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm) : api_(providerKind, aeadAlgorithm, asymmetricAlgorithm, legacyAlgorithm, hashAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm) : api_(providerKind, aeadAlgorithm, asymmetricAlgorithm, legacyAlgorithm, hashAlgorithm, signatureAlgorithm)
{
}
// -----------------------------------------------------------------------------

CScriptCryptoApi::CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm, const KeyAgreementAlgorithm keyAgreementAlgorithm) : api_(providerKind, aeadAlgorithm, asymmetricAlgorithm, legacyAlgorithm, hashAlgorithm, signatureAlgorithm, keyAgreementAlgorithm)
{
}
// -----------------------------------------------------------------------------

std::string CScriptCryptoApi::GetVersion(void) const
{
    try
    {
        return api_.GetVersion();
    }
    catch (...)
    {
        return std::string();
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::EncryptBuffer(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("EncryptBuffer", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.EncryptBuffer(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::DecryptBuffer(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("DecryptBuffer", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.DecryptBuffer(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::EncryptBytes(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("EncryptBytes", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.EncryptBytes(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::DecryptBytes(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("DecryptBytes", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.DecryptBytes(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::EncryptString(const std::string& password, const std::string& input)
{
    return callBinaryOutput("EncryptString", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.EncryptString(password.data(), static_cast<int>(password.size()), input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptCryptoApi::DecryptString(const std::string& password, const std::vector<unsigned char>& input)
{
    return callTextOutput("DecryptString", [this, &password, &input](int capacity, char* buffer, int* actualSize)
    {
        return api_.DecryptString(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApi::EncryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath)
{
    callVoid("EncryptFile", [this, &password, &inputFilePath, &outputFilePath]()
    {
        return api_.EncryptFile(password.c_str(), inputFilePath.c_str(), outputFilePath.c_str(), nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApi::DecryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath)
{
    callVoid("DecryptFile", [this, &password, &inputFilePath, &outputFilePath]()
    {
        return api_.DecryptFile(password.c_str(), inputFilePath.c_str(), outputFilePath.c_str(), nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApi::EncryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath, const ScriptProgressCallback& onProgress)
{
    callVoid("EncryptFile", [this, &password, &inputFilePath, &outputFilePath, &onProgress]()
    {
        ScriptProgressCallback callback = onProgress;
        return api_.EncryptFile(password.c_str(), inputFilePath.c_str(), outputFilePath.c_str(), scriptProgressTrampoline, &callback);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApi::DecryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath, const ScriptProgressCallback& onProgress)
{
    callVoid("DecryptFile", [this, &password, &inputFilePath, &outputFilePath, &onProgress]()
    {
        ScriptProgressCallback callback = onProgress;
        return api_.DecryptFile(password.c_str(), inputFilePath.c_str(), outputFilePath.c_str(), scriptProgressTrampoline, &callback);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApi::GenerateAsymmetricKeyPair(void)
{
    callVoid("GenerateAsymmetricKeyPair", [this]()
    {
        return api_.GenerateAsymmetricKeyPair();
    });
}
// -----------------------------------------------------------------------------

int CScriptCryptoApi::GetMaxAsymmetricPlaintextSize(void) const
{
    try
    {
        return api_.GetMaxAsymmetricPlaintextSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CScriptCryptoApi::GetAsymmetricCiphertextSize(void) const
{
    try
    {
        return api_.GetAsymmetricCiphertextSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::EncryptWithPublicKey(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("EncryptWithPublicKey", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.EncryptWithPublicKey(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::DecryptWithPrivateKey(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("DecryptWithPrivateKey", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.DecryptWithPrivateKey(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::EncryptLegacyBuffer(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("EncryptLegacyBuffer", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.EncryptLegacyBuffer(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::DecryptLegacyBuffer(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("DecryptLegacyBuffer", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.DecryptLegacyBuffer(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

int CScriptCryptoApi::GetHashSize(void) const
{
    try
    {
        return api_.GetHashSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::ComputeHashBuffer(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("ComputeHashBuffer", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.ComputeHashBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::ComputeHashBytes(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("ComputeHashBytes", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.ComputeHashBytes(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::ComputeHashString(const std::string& input)
{
    return callBinaryOutput("ComputeHashString", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.ComputeHashString(input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::ComputeHashFile(const std::string& inputFilePath)
{
    return callBinaryOutput("ComputeHashFile", [this, &inputFilePath](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.ComputeHashFile(inputFilePath.c_str(), capacity, buffer, actualSize, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptCryptoApi::GenerateSignatureKeyPair(void)
{
    callVoid("GenerateSignatureKeyPair", [this]()
    {
        return api_.GenerateSignatureKeyPair();
    });
}
// -----------------------------------------------------------------------------

int CScriptCryptoApi::GetSignatureSize(void) const
{
    try
    {
        return api_.GetSignatureSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::SignBuffer(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("SignBuffer", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.SignBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

bool CScriptCryptoApi::VerifyBuffer(const std::vector<unsigned char>& input, const std::vector<unsigned char>& signature)
{
    try
    {
        bool isValid = false;
        int rc = api_.VerifyBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), signature.empty() ? nullptr : &signature[0], static_cast<int>(signature.size()), &isValid);
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

void CScriptCryptoApi::GenerateKeyAgreementKeyPair(void)
{
    callVoid("GenerateKeyAgreementKeyPair", [this]()
    {
        return api_.GenerateKeyAgreementKeyPair();
    });
}
// -----------------------------------------------------------------------------

int CScriptCryptoApi::GetKeyAgreementPublicKeySize(void) const
{
    try
    {
        return api_.GetKeyAgreementPublicKeySize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CScriptCryptoApi::GetSharedSecretSize(void) const
{
    try
    {
        return api_.GetSharedSecretSize();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::ExportKeyAgreementPublicKey(void)
{
    return callBinaryOutput("ExportKeyAgreementPublicKey", [this](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.ExportKeyAgreementPublicKey(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::DeriveSharedSecret(const std::vector<unsigned char>& peerPublicKey)
{
    return callBinaryOutput("DeriveSharedSecret", [this, &peerPublicKey](int capacity, unsigned char* buffer, int* actualSize)
    {
        return api_.DeriveSharedSecret(peerPublicKey.empty() ? nullptr : &peerPublicKey[0], static_cast<int>(peerPublicKey.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptCryptoApi::GenerateRandomBytes(const int outputSize)
{
    try
    {
        std::vector<unsigned char> output(static_cast<size_t>(outputSize));
        int rc = api_.GenerateRandomBytes(output.empty() ? nullptr : &output[0], outputSize);
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

std::vector<unsigned char> CScriptCryptoApi::GenerateRandomBytes(const RandomAlgorithm randomAlgorithm, const int outputSize)
{
    try
    {
        std::vector<unsigned char> output(static_cast<size_t>(outputSize));
        int rc = api_.GenerateRandomBytes(randomAlgorithm, output.empty() ? nullptr : &output[0], outputSize);
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

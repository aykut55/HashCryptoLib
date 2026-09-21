#include "ScriptPgpEngine.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::vector<unsigned char> CScriptPgpEngine::callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const
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

std::string CScriptPgpEngine::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
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

void CScriptPgpEngine::callVoid(const char* methodName, const std::function<int(void)>& fn) const
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

std::string CScriptPgpEngine::callFixedTextOutput(const char* methodName, const int capacity, const std::function<int(char*, int)>& fn) const
{
    try
    {
        std::vector<char> buffer(static_cast<size_t>(capacity));
        int rc = fn(&buffer[0], capacity);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": call failed");
        }

        return std::string(&buffer[0]);
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

std::vector<std::string> CScriptPgpEngine::callRecordList(const char* methodName, const int recordSize, const std::function<int(int, char*, int*, int*)>& fn) const
{
    try
    {
        int requiredSize = 0;
        int recordCount = 0;
        int rc = fn(0, nullptr, &requiredSize, &recordCount);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": size query failed");
        }

        std::vector<char> buffer(static_cast<size_t>(requiredSize));
        rc = fn(requiredSize, buffer.empty() ? nullptr : &buffer[0], &requiredSize, &recordCount);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), std::string(methodName) + ": call failed");
        }

        std::vector<std::string> records;
        records.reserve(static_cast<size_t>(recordCount));
        for (int recordIndex = 0; recordIndex < recordCount; ++recordIndex)
        {
            records.push_back(std::string(&buffer[static_cast<size_t>(recordIndex) * static_cast<size_t>(recordSize)]));
        }

        return records;
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

CScriptPgpEngine::~CScriptPgpEngine()
{
}
// -----------------------------------------------------------------------------

CScriptPgpEngine::CScriptPgpEngine() : engine_()
{
}
// -----------------------------------------------------------------------------

CScriptPgpEngine::CScriptPgpEngine(const int rsaKeyBits) : engine_(rsaKeyBits)
{
}
// -----------------------------------------------------------------------------

CScriptPgpEngine::CScriptPgpEngine(const PgpKeyAlgorithm keyAlgorithm) : engine_(keyAlgorithm)
{
}
// -----------------------------------------------------------------------------

PgpKeyAlgorithm CScriptPgpEngine::GetKeyAlgorithm(void) const
{
    return engine_.GetKeyAlgorithm();
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::GenerateKeyPair(const std::string& userId, const std::string& password)
{
    callVoid("GenerateKeyPair", [this, &userId, &password]()
    {
        return engine_.GenerateKeyPair(userId.data(), static_cast<int>(userId.size()), password.data(), static_cast<int>(password.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::GenerateKeyPair(const std::string& userId, const std::string& password, const unsigned int expirationSeconds)
{
    callVoid("GenerateKeyPair", [this, &userId, &password, expirationSeconds]()
    {
        return engine_.GenerateKeyPair(userId.data(), static_cast<int>(userId.size()), password.data(), static_cast<int>(password.size()), expirationSeconds);
    });
}
// -----------------------------------------------------------------------------

unsigned int CScriptPgpEngine::GetKeyExpirationSeconds(void) const
{
    return engine_.GetKeyExpirationSeconds();
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngine::ExportPublicKeyArmored(void)
{
    return callTextOutput("ExportPublicKeyArmored", [this](int capacity, char* buffer, int* actualSize)
    {
        return engine_.ExportPublicKeyArmored(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngine::ExportSecretKeyArmored(void)
{
    return callTextOutput("ExportSecretKeyArmored", [this](int capacity, char* buffer, int* actualSize)
    {
        return engine_.ExportSecretKeyArmored(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngine::GetKeyId(void) const
{
    return callFixedTextOutput("GetKeyId", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this](char* buffer, int capacity)
    {
        return engine_.GetKeyId(buffer, capacity);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngine::RevokeKeyArmored(const std::string& password, const unsigned char reasonCode, const std::string& reasonText)
{
    return callTextOutput("RevokeKeyArmored", [this, &password, reasonCode, &reasonText](int capacity, char* buffer, int* actualSize)
    {
        return engine_.RevokeKeyArmored(password.data(), static_cast<int>(password.size()), reasonCode, reasonText.data(), static_cast<int>(reasonText.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::ImportPeerPublicKey(const std::vector<unsigned char>& keyBlock)
{
    callVoid("ImportPeerPublicKey", [this, &keyBlock]()
    {
        return engine_.ImportPeerPublicKey(keyBlock.empty() ? nullptr : &keyBlock[0], static_cast<int>(keyBlock.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::ImportPeerPublicKey(const std::string& keyBlockArmored)
{
    callVoid("ImportPeerPublicKey", [this, &keyBlockArmored]()
    {
        return engine_.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(keyBlockArmored.data()), static_cast<int>(keyBlockArmored.size()));
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngine::GetPeerKeyId(void) const
{
    return callFixedTextOutput("GetPeerKeyId", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this](char* buffer, int capacity)
    {
        return engine_.GetPeerKeyId(buffer, capacity);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::ImportAdditionalRecipientPublicKey(const std::vector<unsigned char>& keyBlock)
{
    callVoid("ImportAdditionalRecipientPublicKey", [this, &keyBlock]()
    {
        return engine_.ImportAdditionalRecipientPublicKey(keyBlock.empty() ? nullptr : &keyBlock[0], static_cast<int>(keyBlock.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::ImportAdditionalRecipientPublicKey(const std::string& keyBlockArmored)
{
    callVoid("ImportAdditionalRecipientPublicKey", [this, &keyBlockArmored]()
    {
        return engine_.ImportAdditionalRecipientPublicKey(reinterpret_cast<const unsigned char*>(keyBlockArmored.data()), static_cast<int>(keyBlockArmored.size()));
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngine::EncryptBuffer(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("EncryptBuffer", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engine_.EncryptBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngine::EncryptStringArmored(const std::string& input)
{
    return callTextOutput("EncryptStringArmored", [this, &input](int capacity, char* buffer, int* actualSize)
    {
        return engine_.EncryptStringArmored(input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngine::DecryptBuffer(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("DecryptBuffer", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engine_.DecryptBuffer(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngine::DecryptStringArmored(const std::string& password, const std::string& input)
{
    return callBinaryOutput("DecryptStringArmored", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engine_.DecryptStringArmored(password.data(), static_cast<int>(password.size()), input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngine::SignBuffer(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("SignBuffer", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engine_.SignBuffer(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngine::VerifyBuffer(const std::vector<unsigned char>& input, const std::vector<unsigned char>& signature)
{
    try
    {
        bool isValid = false;
        int rc = engine_.VerifyBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), signature.empty() ? nullptr : &signature[0], static_cast<int>(signature.size()), &isValid);
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

std::string CScriptPgpEngine::ClearSignString(const std::string& password, const std::string& input)
{
    return callTextOutput("ClearSignString", [this, &password, &input](int capacity, char* buffer, int* actualSize)
    {
        return engine_.ClearSignString(password.data(), static_cast<int>(password.size()), input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngine::VerifyClearSignedString(const std::string& clearSignedString)
{
    try
    {
        bool isValid = false;
        int rc = engine_.VerifyClearSignedString(clearSignedString.data(), static_cast<int>(clearSignedString.size()), &isValid);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "VerifyClearSignedString: verification could not run");
        }

        return isValid;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("VerifyClearSignedString: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::EncryptFile(const std::string& inputFilePath, const std::string& outputFilePath)
{
    callVoid("EncryptFile", [this, &inputFilePath, &outputFilePath]()
    {
        return engine_.EncryptFile(inputFilePath.c_str(), outputFilePath.c_str(), nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::EncryptFileCompressed(const std::string& inputFilePath, const std::string& outputFilePath, const PgpFileCompressionAlgorithm compressionAlgorithm)
{
    callVoid("EncryptFileCompressed", [this, &inputFilePath, &outputFilePath, compressionAlgorithm]()
    {
        return engine_.EncryptFileCompressed(inputFilePath.c_str(), outputFilePath.c_str(), compressionAlgorithm, nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::DecryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath)
{
    callVoid("DecryptFile", [this, &password, &inputFilePath, &outputFilePath]()
    {
        return engine_.DecryptFile(password.data(), static_cast<int>(password.size()), inputFilePath.c_str(), outputFilePath.c_str(), nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngine::SignFile(const std::string& password, const std::string& inputFilePath, const std::string& signatureFilePath)
{
    callVoid("SignFile", [this, &password, &inputFilePath, &signatureFilePath]()
    {
        return engine_.SignFile(password.data(), static_cast<int>(password.size()), inputFilePath.c_str(), signatureFilePath.c_str(), nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngine::VerifyFile(const std::string& inputFilePath, const std::string& signatureFilePath)
{
    try
    {
        bool isValid = false;
        int rc = engine_.VerifyFile(inputFilePath.c_str(), signatureFilePath.c_str(), &isValid, nullptr, nullptr);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "VerifyFile: verification could not run");
        }

        return isValid;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("VerifyFile: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngine::IsPublicKeyEncrypted(const std::vector<unsigned char>& input) const
{
    try
    {
        bool isPublicKeyEncrypted = false;
        int rc = engine_.IsPublicKeyEncrypted(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), &isPublicKeyEncrypted);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "IsPublicKeyEncrypted: call failed");
        }

        return isPublicKeyEncrypted;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("IsPublicKeyEncrypted: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngine::IsPasswordEncrypted(const std::vector<unsigned char>& input) const
{
    try
    {
        bool isPasswordEncrypted = false;
        int rc = engine_.IsPasswordEncrypted(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), &isPasswordEncrypted);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "IsPasswordEncrypted: call failed");
        }

        return isPasswordEncrypted;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("IsPasswordEncrypted: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngine::IsIntegrityProtected(const std::vector<unsigned char>& input) const
{
    try
    {
        bool isIntegrityProtected = false;
        int rc = engine_.IsIntegrityProtected(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), &isIntegrityProtected);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "IsIntegrityProtected: call failed");
        }

        return isIntegrityProtected;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("IsIntegrityProtected: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

int CScriptPgpEngine::GetCompression(const std::vector<unsigned char>& input) const
{
    try
    {
        int compressionAlgorithm = 0;
        int rc = engine_.GetCompression(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), &compressionAlgorithm);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "GetCompression: call failed");
        }

        return compressionAlgorithm;
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("GetCompression: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

std::vector<std::string> CScriptPgpEngine::ListEncryptionKeyIds(const std::vector<unsigned char>& input) const
{
    return callRecordList("ListEncryptionKeyIds", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this, &input](int capacity, char* buffer, int* actualSize, int* recordCount)
    {
        return engine_.ListEncryptionKeyIds(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, recordCount);
    });
}
// -----------------------------------------------------------------------------

std::vector<std::string> CScriptPgpEngine::ListSigningKeyIds(const std::vector<unsigned char>& input) const
{
    return callRecordList("ListSigningKeyIds", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this, &input](int capacity, char* buffer, int* actualSize, int* recordCount)
    {
        return engine_.ListSigningKeyIds(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, recordCount);
    });
}
// -----------------------------------------------------------------------------

std::vector<std::string> CScriptPgpEngine::ListSignatures(const std::vector<unsigned char>& input) const
{
    return callRecordList("ListSignatures", PGP_INSPECTION_SIGNATURE_RECORD_SIZE, [this, &input](int capacity, char* buffer, int* actualSize, int* recordCount)
    {
        return engine_.ListSignatures(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, recordCount);
    });
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#include "ScriptPgpEngineWrapper.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::vector<unsigned char> CScriptPgpEngineWrapper::callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const
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

std::string CScriptPgpEngineWrapper::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
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

void CScriptPgpEngineWrapper::callVoid(const char* methodName, const std::function<int(void)>& fn) const
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

std::string CScriptPgpEngineWrapper::callFixedTextOutput(const char* methodName, const int capacity, const std::function<int(char*, int)>& fn) const
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

std::vector<std::string> CScriptPgpEngineWrapper::callRecordList(const char* methodName, const int recordSize, const std::function<int(int, char*, int*, int*)>& fn) const
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

CScriptPgpEngineWrapper::~CScriptPgpEngineWrapper()
{
}
// -----------------------------------------------------------------------------

CScriptPgpEngineWrapper::CScriptPgpEngineWrapper() : engineWrapper_()
{
}
// -----------------------------------------------------------------------------

CScriptPgpEngineWrapper::CScriptPgpEngineWrapper(const int rsaKeyBits) : engineWrapper_(rsaKeyBits)
{
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngineWrapper::IsGnuPgAvailable(void) const
{
    return engineWrapper_.IsGnuPgAvailable();
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::GenerateKeyPair(const std::string& userId, const std::string& password)
{
    callVoid("GenerateKeyPair", [this, &userId, &password]()
    {
        return engineWrapper_.GenerateKeyPair(userId.data(), static_cast<int>(userId.size()), password.data(), static_cast<int>(password.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::GenerateKeyPair(const std::string& userId, const std::string& password, const unsigned int expirationSeconds)
{
    callVoid("GenerateKeyPair", [this, &userId, &password, expirationSeconds]()
    {
        return engineWrapper_.GenerateKeyPair(userId.data(), static_cast<int>(userId.size()), password.data(), static_cast<int>(password.size()), expirationSeconds);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::GenerateKeyPairEcc(const std::string& userId, const std::string& password)
{
    callVoid("GenerateKeyPairEcc", [this, &userId, &password]()
    {
        return engineWrapper_.GenerateKeyPairEcc(userId.data(), static_cast<int>(userId.size()), password.data(), static_cast<int>(password.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::GenerateKeyPairEcc(const std::string& userId, const std::string& password, const unsigned int expirationSeconds)
{
    callVoid("GenerateKeyPairEcc", [this, &userId, &password, expirationSeconds]()
    {
        return engineWrapper_.GenerateKeyPairEcc(userId.data(), static_cast<int>(userId.size()), password.data(), static_cast<int>(password.size()), expirationSeconds);
    });
}
// -----------------------------------------------------------------------------

unsigned int CScriptPgpEngineWrapper::GetKeyExpirationSeconds(void) const
{
    return engineWrapper_.GetKeyExpirationSeconds();
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::ExportPublicKeyArmored(void)
{
    return callTextOutput("ExportPublicKeyArmored", [this](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.ExportPublicKeyArmored(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::ExportSecretKeyArmored(void)
{
    return callTextOutput("ExportSecretKeyArmored", [this](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.ExportSecretKeyArmored(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::GetKeyId(void) const
{
    return callFixedTextOutput("GetKeyId", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this](char* buffer, int capacity)
    {
        return engineWrapper_.GetKeyId(buffer, capacity);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::RevokeKeyArmored(const std::string& password, const unsigned char reasonCode, const std::string& reasonText)
{
    return callTextOutput("RevokeKeyArmored", [this, &password, reasonCode, &reasonText](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.RevokeKeyArmored(password.data(), static_cast<int>(password.size()), reasonCode, reasonText.data(), static_cast<int>(reasonText.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::ImportPeerPublicKey(const std::vector<unsigned char>& keyBlock)
{
    callVoid("ImportPeerPublicKey", [this, &keyBlock]()
    {
        return engineWrapper_.ImportPeerPublicKey(keyBlock.empty() ? nullptr : &keyBlock[0], static_cast<int>(keyBlock.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::ImportPeerPublicKey(const std::string& keyBlockArmored)
{
    callVoid("ImportPeerPublicKey", [this, &keyBlockArmored]()
    {
        return engineWrapper_.ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(keyBlockArmored.data()), static_cast<int>(keyBlockArmored.size()));
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::GetPeerKeyId(void) const
{
    return callFixedTextOutput("GetPeerKeyId", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this](char* buffer, int capacity)
    {
        return engineWrapper_.GetPeerKeyId(buffer, capacity);
    });
}
// -----------------------------------------------------------------------------

int CScriptPgpEngineWrapper::GetImportedPeerKeyCount(void) const
{
    return engineWrapper_.GetImportedPeerKeyCount();
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::GetImportedPeerKeyId(const int peerIndex) const
{
    return callFixedTextOutput("GetImportedPeerKeyId", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this, peerIndex](char* buffer, int capacity)
    {
        return engineWrapper_.GetImportedPeerKeyId(peerIndex, buffer, capacity);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::GetKeyringListing(void) const
{
    return callTextOutput("GetKeyringListing", [this](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.GetKeyringListing(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

int CScriptPgpEngineWrapper::GetKeyringKeyCount(void) const
{
    return engineWrapper_.GetKeyringKeyCount();
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::GetKeyringKeyId(const int keyIndex) const
{
    return callFixedTextOutput("GetKeyringKeyId", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this, keyIndex](char* buffer, int capacity)
    {
        return engineWrapper_.GetKeyringKeyId(keyIndex, buffer, capacity);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::DeletePeerPublicKey(const std::string& keyId)
{
    callVoid("DeletePeerPublicKey", [this, &keyId]()
    {
        return engineWrapper_.DeletePeerPublicKey(keyId.data(), static_cast<int>(keyId.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::DeleteOwnIdentity(void)
{
    callVoid("DeleteOwnIdentity", [this]()
    {
        return engineWrapper_.DeleteOwnIdentity();
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapper::EncryptBuffer(const std::vector<unsigned char>& input)
{
    return callBinaryOutput("EncryptBuffer", [this, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapper::EncryptBuffer(const std::vector<unsigned char>& input, const PgpCompressionAlgorithm compressionAlgorithm)
{
    return callBinaryOutput("EncryptBuffer", [this, &input, compressionAlgorithm](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), compressionAlgorithm, capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::EncryptStringArmored(const std::string& input)
{
    return callTextOutput("EncryptStringArmored", [this, &input](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptStringArmored(input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::EncryptStringArmored(const std::string& input, const PgpCompressionAlgorithm compressionAlgorithm)
{
    return callTextOutput("EncryptStringArmored", [this, &input, compressionAlgorithm](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptStringArmored(input.data(), static_cast<int>(input.size()), compressionAlgorithm, capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapper::EncryptBufferSymmetric(const std::string& passphrase, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("EncryptBufferSymmetric", [this, &passphrase, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptBufferSymmetric(passphrase.data(), static_cast<int>(passphrase.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::EncryptStringArmoredSymmetric(const std::string& passphrase, const std::string& input)
{
    return callTextOutput("EncryptStringArmoredSymmetric", [this, &passphrase, &input](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptStringArmoredSymmetric(passphrase.data(), static_cast<int>(passphrase.size()), input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapper::EncryptBufferMultiRecipient(const std::vector<unsigned char>& input, const std::vector<std::string>& recipientKeyIds)
{
    std::vector<const char*> recipientPointers;
    recipientPointers.reserve(recipientKeyIds.size());
    for (const std::string& recipientKeyId : recipientKeyIds)
    {
        recipientPointers.push_back(recipientKeyId.c_str());
    }

    return callBinaryOutput("EncryptBufferMultiRecipient", [this, &input, &recipientPointers](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptBufferMultiRecipient(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), recipientPointers.empty() ? nullptr : &recipientPointers[0], static_cast<int>(recipientPointers.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapper::EncryptBufferMultiRecipient(const std::vector<unsigned char>& input, const std::vector<std::string>& recipientKeyIds, const PgpCompressionAlgorithm compressionAlgorithm)
{
    std::vector<const char*> recipientPointers;
    recipientPointers.reserve(recipientKeyIds.size());
    for (const std::string& recipientKeyId : recipientKeyIds)
    {
        recipientPointers.push_back(recipientKeyId.c_str());
    }

    return callBinaryOutput("EncryptBufferMultiRecipient", [this, &input, &recipientPointers, compressionAlgorithm](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptBufferMultiRecipient(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), recipientPointers.empty() ? nullptr : &recipientPointers[0], static_cast<int>(recipientPointers.size()), compressionAlgorithm, capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient(const std::string& input, const std::vector<std::string>& recipientKeyIds)
{
    std::vector<const char*> recipientPointers;
    recipientPointers.reserve(recipientKeyIds.size());
    for (const std::string& recipientKeyId : recipientKeyIds)
    {
        recipientPointers.push_back(recipientKeyId.c_str());
    }

    return callTextOutput("EncryptStringArmoredMultiRecipient", [this, &input, &recipientPointers](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptStringArmoredMultiRecipient(input.data(), static_cast<int>(input.size()), recipientPointers.empty() ? nullptr : &recipientPointers[0], static_cast<int>(recipientPointers.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient(const std::string& input, const std::vector<std::string>& recipientKeyIds, const PgpCompressionAlgorithm compressionAlgorithm)
{
    std::vector<const char*> recipientPointers;
    recipientPointers.reserve(recipientKeyIds.size());
    for (const std::string& recipientKeyId : recipientKeyIds)
    {
        recipientPointers.push_back(recipientKeyId.c_str());
    }

    return callTextOutput("EncryptStringArmoredMultiRecipient", [this, &input, &recipientPointers, compressionAlgorithm](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.EncryptStringArmoredMultiRecipient(input.data(), static_cast<int>(input.size()), recipientPointers.empty() ? nullptr : &recipientPointers[0], static_cast<int>(recipientPointers.size()), compressionAlgorithm, capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapper::DecryptBuffer(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("DecryptBuffer", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engineWrapper_.DecryptBuffer(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapper::DecryptStringArmored(const std::string& password, const std::string& input)
{
    return callBinaryOutput("DecryptStringArmored", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engineWrapper_.DecryptStringArmored(password.data(), static_cast<int>(password.size()), input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapper::SignBuffer(const std::string& password, const std::vector<unsigned char>& input)
{
    return callBinaryOutput("SignBuffer", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return engineWrapper_.SignBuffer(password.data(), static_cast<int>(password.size()), input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngineWrapper::VerifyBuffer(const std::vector<unsigned char>& input, const std::vector<unsigned char>& signature)
{
    try
    {
        bool isValid = false;
        int rc = engineWrapper_.VerifyBuffer(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), signature.empty() ? nullptr : &signature[0], static_cast<int>(signature.size()), &isValid);
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

std::string CScriptPgpEngineWrapper::ClearSignString(const std::string& password, const std::string& input)
{
    return callTextOutput("ClearSignString", [this, &password, &input](int capacity, char* buffer, int* actualSize)
    {
        return engineWrapper_.ClearSignString(password.data(), static_cast<int>(password.size()), input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngineWrapper::VerifyClearSignedString(const std::string& clearSignedString)
{
    try
    {
        bool isValid = false;
        int rc = engineWrapper_.VerifyClearSignedString(clearSignedString.data(), static_cast<int>(clearSignedString.size()), &isValid);
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

void CScriptPgpEngineWrapper::EncryptFile(const std::string& inputFilePath, const std::string& outputFilePath)
{
    callVoid("EncryptFile", [this, &inputFilePath, &outputFilePath]()
    {
        return engineWrapper_.EncryptFile(inputFilePath.c_str(), outputFilePath.c_str(), nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::DecryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath)
{
    callVoid("DecryptFile", [this, &password, &inputFilePath, &outputFilePath]()
    {
        return engineWrapper_.DecryptFile(password.data(), static_cast<int>(password.size()), inputFilePath.c_str(), outputFilePath.c_str(), nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapper::SignFile(const std::string& password, const std::string& inputFilePath, const std::string& signatureFilePath)
{
    callVoid("SignFile", [this, &password, &inputFilePath, &signatureFilePath]()
    {
        return engineWrapper_.SignFile(password.data(), static_cast<int>(password.size()), inputFilePath.c_str(), signatureFilePath.c_str(), nullptr, nullptr);
    });
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngineWrapper::VerifyFile(const std::string& inputFilePath, const std::string& signatureFilePath)
{
    try
    {
        bool isValid = false;
        int rc = engineWrapper_.VerifyFile(inputFilePath.c_str(), signatureFilePath.c_str(), &isValid, nullptr, nullptr);
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

bool CScriptPgpEngineWrapper::IsPublicKeyEncrypted(const std::vector<unsigned char>& input) const
{
    try
    {
        bool isPublicKeyEncrypted = false;
        int rc = engineWrapper_.IsPublicKeyEncrypted(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), &isPublicKeyEncrypted);
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

bool CScriptPgpEngineWrapper::IsPasswordEncrypted(const std::vector<unsigned char>& input) const
{
    try
    {
        bool isPasswordEncrypted = false;
        int rc = engineWrapper_.IsPasswordEncrypted(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), &isPasswordEncrypted);
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

bool CScriptPgpEngineWrapper::IsIntegrityProtected(const std::vector<unsigned char>& input) const
{
    try
    {
        bool isIntegrityProtected = false;
        int rc = engineWrapper_.IsIntegrityProtected(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), &isIntegrityProtected);
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

int CScriptPgpEngineWrapper::GetCompression(const std::vector<unsigned char>& input) const
{
    try
    {
        int compressionAlgorithm = 0;
        int rc = engineWrapper_.GetCompression(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), &compressionAlgorithm);
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

std::vector<std::string> CScriptPgpEngineWrapper::ListEncryptionKeyIds(const std::vector<unsigned char>& input) const
{
    return callRecordList("ListEncryptionKeyIds", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this, &input](int capacity, char* buffer, int* actualSize, int* recordCount)
    {
        return engineWrapper_.ListEncryptionKeyIds(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, recordCount);
    });
}
// -----------------------------------------------------------------------------

std::vector<std::string> CScriptPgpEngineWrapper::ListSigningKeyIds(const std::vector<unsigned char>& input) const
{
    return callRecordList("ListSigningKeyIds", PGP_INSPECTION_KEY_ID_RECORD_SIZE, [this, &input](int capacity, char* buffer, int* actualSize, int* recordCount)
    {
        return engineWrapper_.ListSigningKeyIds(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, recordCount);
    });
}
// -----------------------------------------------------------------------------

std::vector<std::string> CScriptPgpEngineWrapper::ListSignatures(const std::vector<unsigned char>& input) const
{
    return callRecordList("ListSignatures", PGP_INSPECTION_SIGNATURE_RECORD_SIZE, [this, &input](int capacity, char* buffer, int* actualSize, int* recordCount)
    {
        return engineWrapper_.ListSignatures(input.empty() ? nullptr : &input[0], static_cast<int>(input.size()), capacity, buffer, actualSize, recordCount);
    });
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#include "ScriptPgpEngineWrapperDll.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::vector<unsigned char> CScriptPgpEngineWrapperDll::callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const
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

std::string CScriptPgpEngineWrapperDll::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
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

void CScriptPgpEngineWrapperDll::callVoid(const char* methodName, const std::function<int(void)>& fn) const
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

CScriptPgpEngineWrapperDll::~CScriptPgpEngineWrapperDll()
{
}
// -----------------------------------------------------------------------------

CScriptPgpEngineWrapperDll::CScriptPgpEngineWrapperDll(IPgpEngineWrapper* wrapper) : wrapper_(wrapper)
{
}
// -----------------------------------------------------------------------------

bool CScriptPgpEngineWrapperDll::IsGnuPgAvailable(void) const
{
    return wrapper_->IsGnuPgAvailable();
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapperDll::GenerateKeyPair(const std::string& userId, const std::string& password)
{
    callVoid("GenerateKeyPair", [this, &userId, &password]()
    {
        return wrapper_->GenerateKeyPair(userId.data(), static_cast<int>(userId.size()), password.data(), static_cast<int>(password.size()));
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapperDll::ExportPublicKeyArmored(void)
{
    return callTextOutput("ExportPublicKeyArmored", [this](int capacity, char* buffer, int* actualSize)
    {
        return wrapper_->ExportPublicKeyArmored(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

void CScriptPgpEngineWrapperDll::ImportPeerPublicKey(const std::string& keyBlockArmored)
{
    callVoid("ImportPeerPublicKey", [this, &keyBlockArmored]()
    {
        return wrapper_->ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(keyBlockArmored.data()), static_cast<int>(keyBlockArmored.size()));
    });
}
// -----------------------------------------------------------------------------

std::string CScriptPgpEngineWrapperDll::EncryptStringArmored(const std::string& input)
{
    return callTextOutput("EncryptStringArmored", [this, &input](int capacity, char* buffer, int* actualSize)
    {
        return wrapper_->EncryptStringArmored(input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> CScriptPgpEngineWrapperDll::DecryptStringArmored(const std::string& password, const std::string& input)
{
    return callBinaryOutput("DecryptStringArmored", [this, &password, &input](int capacity, unsigned char* buffer, int* actualSize)
    {
        return wrapper_->DecryptStringArmored(password.data(), static_cast<int>(password.size()), input.data(), static_cast<int>(input.size()), capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

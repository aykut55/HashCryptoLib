#include "ScriptSshManager.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::string CScriptSshManager::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
{
    try
    {
        int requiredSize = 0;
        int rc = fn(0, nullptr, &requiredSize);
        // (No retry loop needed here -- every callTextOutput caller inspects EXISTING, already-
        // generated data, so its output length is deterministic given the same input, same
        // reasoning as CScriptCertificateManager's own identical helper.)
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

void CScriptSshManager::callVoid(const char* methodName, const std::function<int(void)>& fn)
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

CScriptSshManager::~CScriptSshManager()
{
}
// -----------------------------------------------------------------------------

CScriptSshManager::CScriptSshManager() : engine_(), lastExecExitStatus_(-1)
{
}
// -----------------------------------------------------------------------------

bool CScriptSshManager::Connect(const std::string& host, const int port, const int timeoutMs)
{
    const int status = engine_.Connect( host.data(), static_cast<int>(host.size()),
                                        static_cast<unsigned short>(port), static_cast<unsigned int>(timeoutMs));
    return status == NO_ERROR;
}
// -----------------------------------------------------------------------------

void CScriptSshManager::Disconnect(void)
{
    callVoid("Disconnect", [this]()
    {
        return engine_.Disconnect();
    });
}
// -----------------------------------------------------------------------------

bool CScriptSshManager::IsConnected(void) const
{
    return engine_.IsConnected();
}
// -----------------------------------------------------------------------------

std::string CScriptSshManager::GetHostKeyFingerprint(void) const
{
    return callTextOutput("GetHostKeyFingerprint", [this](int capacity, char* buffer, int* actualSize)
    {
        return engine_.GetHostKeyFingerprint(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

int CScriptSshManager::CheckKnownHost(const std::string& knownHostsFilePath)
{
    try
    {
        SshHostKeyCheckResult result = SSH_HOST_KEY_CHECK_FAILED;
        const int rc = engine_.CheckKnownHost(knownHostsFilePath.data(), static_cast<int>(knownHostsFilePath.size()), &result);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "CheckKnownHost: call failed");
        }
        return static_cast<int>(result);
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("CheckKnownHost: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

void CScriptSshManager::AddKnownHost(const std::string& knownHostsFilePath, const std::string& hostNameForEntry)
{
    callVoid("AddKnownHost", [this, &knownHostsFilePath, &hostNameForEntry]()
    {
        return engine_.AddKnownHost( knownHostsFilePath.data(), static_cast<int>(knownHostsFilePath.size()),
                                    hostNameForEntry.data(), static_cast<int>(hostNameForEntry.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptSshManager::AuthenticatePassword(const std::string& username, const std::string& password)
{
    callVoid("AuthenticatePassword", [this, &username, &password]()
    {
        return engine_.AuthenticatePassword( username.data(), static_cast<int>(username.size()),
                                            password.data(), static_cast<int>(password.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptSshManager::AuthenticatePublicKey( const std::string& username, const std::string& publicKeyFilePath,
                                              const std::string& privateKeyFilePath, const std::string& passphrase)
{
    callVoid("AuthenticatePublicKey", [this, &username, &publicKeyFilePath, &privateKeyFilePath, &passphrase]()
    {
        return engine_.AuthenticatePublicKey( username.data(), static_cast<int>(username.size()),
                                             publicKeyFilePath.empty() ? nullptr : publicKeyFilePath.data(), static_cast<int>(publicKeyFilePath.size()),
                                             privateKeyFilePath.data(), static_cast<int>(privateKeyFilePath.size()),
                                             passphrase.empty() ? nullptr : passphrase.data(), static_cast<int>(passphrase.size()));
    });
}
// -----------------------------------------------------------------------------

bool CScriptSshManager::IsAuthenticated(void) const
{
    return engine_.IsAuthenticated();
}
// -----------------------------------------------------------------------------

std::string CScriptSshManager::ExecuteCommand(const std::string& command)
{
    try
    {
        int stdoutRequiredSize = 0;
        int stderrRequiredSize = 0;
        int exitStatus = -1;
        int rc = engine_.ExecuteCommand( command.data(), static_cast<int>(command.size()),
                                        0, nullptr, &stdoutRequiredSize,
                                        0, nullptr, &stderrRequiredSize, &exitStatus);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "ExecuteCommand: size query failed");
        }

        std::vector<char> stdoutBuffer(static_cast<size_t>(stdoutRequiredSize));
        std::vector<char> stderrBuffer(static_cast<size_t>(stderrRequiredSize));
        rc = engine_.ExecuteCommand( command.data(), static_cast<int>(command.size()),
                                    stdoutRequiredSize, stdoutBuffer.empty() ? nullptr : &stdoutBuffer[0], &stdoutRequiredSize,
                                    stderrRequiredSize, stderrBuffer.empty() ? nullptr : &stderrBuffer[0], &stderrRequiredSize, &exitStatus);
        if (rc != NO_ERROR)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "ExecuteCommand: call failed");
        }

        lastExecStderr_.assign(stderrBuffer.empty() ? "" : &stderrBuffer[0], static_cast<size_t>(stderrRequiredSize));
        lastExecExitStatus_ = exitStatus;
        return std::string(stdoutBuffer.empty() ? "" : &stdoutBuffer[0], static_cast<size_t>(stdoutRequiredSize));
    }
    catch (const CScriptException&)
    {
        throw;
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("ExecuteCommand: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

std::string CScriptSshManager::GetLastExecStderr(void) const
{
    return lastExecStderr_;
}
// -----------------------------------------------------------------------------

int CScriptSshManager::GetLastExecExitStatus(void) const
{
    return lastExecExitStatus_;
}
// -----------------------------------------------------------------------------

void CScriptSshManager::SftpUploadFile(const std::string& localFilePath, const std::string& remoteFilePath)
{
    callVoid("SftpUploadFile", [this, &localFilePath, &remoteFilePath]()
    {
        return engine_.SftpUploadFile( localFilePath.data(), static_cast<int>(localFilePath.size()),
                                      remoteFilePath.data(), static_cast<int>(remoteFilePath.size()));
    });
}
// -----------------------------------------------------------------------------

void CScriptSshManager::SftpDownloadFile(const std::string& remoteFilePath, const std::string& localFilePath)
{
    callVoid("SftpDownloadFile", [this, &remoteFilePath, &localFilePath]()
    {
        return engine_.SftpDownloadFile( remoteFilePath.data(), static_cast<int>(remoteFilePath.size()),
                                        localFilePath.data(), static_cast<int>(localFilePath.size()));
    });
}
// -----------------------------------------------------------------------------

std::string CScriptSshManager::GetLastErrorMessage(void) const
{
    return callTextOutput("GetLastErrorMessage", [this](int capacity, char* buffer, int* actualSize)
    {
        return engine_.GetLastErrorMessage(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#include "ScriptSshManagerDll.h"
#include "ScriptException.h"

namespace CryptoApiNS
{

std::string CScriptSshManagerDll::callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const
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

void CScriptSshManagerDll::callVoid(const char* methodName, const std::function<int(void)>& fn)
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

CScriptSshManagerDll::~CScriptSshManagerDll()
{
}
// -----------------------------------------------------------------------------

CScriptSshManagerDll::CScriptSshManagerDll(ISshManager* manager) : manager_(manager), lastExecExitStatus_(-1)
{
}
// -----------------------------------------------------------------------------

bool CScriptSshManagerDll::Connect(const std::string& host, const int port, const int timeoutMs)
{
    const int status = manager_->Connect( host.data(), static_cast<int>(host.size()),
                                         static_cast<unsigned short>(port), static_cast<unsigned int>(timeoutMs));
    return status == NO_ERROR;
}
// -----------------------------------------------------------------------------

void CScriptSshManagerDll::Disconnect(void)
{
    callVoid("Disconnect", [this]()
    {
        return manager_->Disconnect();
    });
}
// -----------------------------------------------------------------------------

std::string CScriptSshManagerDll::GetHostKeyFingerprint(void) const
{
    return callTextOutput("GetHostKeyFingerprint", [this](int capacity, char* buffer, int* actualSize)
    {
        return manager_->GetHostKeyFingerprint(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

void CScriptSshManagerDll::AuthenticatePassword(const std::string& username, const std::string& password)
{
    callVoid("AuthenticatePassword", [this, &username, &password]()
    {
        return manager_->AuthenticatePassword( username.data(), static_cast<int>(username.size()),
                                              password.data(), static_cast<int>(password.size()));
    });
}
// -----------------------------------------------------------------------------

std::string CScriptSshManagerDll::ExecuteCommand(const std::string& command)
{
    try
    {
        int stdoutRequiredSize = 0;
        int stderrRequiredSize = 0;
        int exitStatus = -1;
        int rc = manager_->ExecuteCommand( command.data(), static_cast<int>(command.size()),
                                          0, nullptr, &stdoutRequiredSize,
                                          0, nullptr, &stderrRequiredSize, &exitStatus);
        if (rc != NO_ERROR && rc != BUFFER_TOO_SMALL)
        {
            throw CScriptException(static_cast<ErrorCode>(rc), "ExecuteCommand: size query failed");
        }

        std::vector<char> stdoutBuffer(static_cast<size_t>(stdoutRequiredSize));
        std::vector<char> stderrBuffer(static_cast<size_t>(stderrRequiredSize));
        rc = manager_->ExecuteCommand( command.data(), static_cast<int>(command.size()),
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

std::string CScriptSshManagerDll::GetLastExecStderr(void) const
{
    return lastExecStderr_;
}
// -----------------------------------------------------------------------------

int CScriptSshManagerDll::GetLastExecExitStatus(void) const
{
    return lastExecExitStatus_;
}
// -----------------------------------------------------------------------------

std::string CScriptSshManagerDll::GetLastErrorMessage(void) const
{
    return callTextOutput("GetLastErrorMessage", [this](int capacity, char* buffer, int* actualSize)
    {
        return manager_->GetLastErrorMessage(capacity, buffer, actualSize);
    });
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

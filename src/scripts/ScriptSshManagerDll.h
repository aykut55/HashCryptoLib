#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_SSH_MANAGER_DLL_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_SSH_MANAGER_DLL_H

#include "Interfaces/ISshManager.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// DLL-hosted counterpart to CScriptSshManager -- wraps an ISshManager* obtained via
// CCryptoApiDllLoader::GetSshManagerObject() instead of owning a concrete CSshManager. Same
// reasoning as CScriptCertificateManagerDll's own header comment: method surface reduced to a
// connect -> authenticate -> execute -> disconnect round trip (the minimum needed for a meaningful
// demo), not a full mirror of CScriptSshManager -- no host-key-pinning or SFTP methods here. The
// wrapped ISshManager* is never owned/deleted here.
class CScriptSshManagerDll
{
public:
    virtual ~CScriptSshManagerDll();
    explicit CScriptSshManagerDll(ISshManager* manager);

    // Returns false (not a thrown exception) on failure -- see CScriptSshManager.h's own header
    // comment for why Connect is this class's one deliberate non-throwing method.
    bool Connect(const std::string& host, const int port, const int timeoutMs);
    void Disconnect(void);

    std::string GetHostKeyFingerprint(void) const;

    void AuthenticatePassword(const std::string& username, const std::string& password);

    // Same "stash stderr/exit status" convention as CScriptSshManager's own ExecuteCommand.
    std::string ExecuteCommand(const std::string& command);
    std::string GetLastExecStderr(void) const;
    int GetLastExecExitStatus(void) const;

    std::string GetLastErrorMessage(void) const;

protected:

private:

    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;
    void callVoid(const char* methodName, const std::function<int(void)>& fn);

    ISshManager* manager_;
    std::string lastExecStderr_;
    int lastExecExitStatus_;

};

} // namespace CryptoApiNS

#endif

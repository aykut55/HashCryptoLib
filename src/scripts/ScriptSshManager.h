#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_SSH_MANAGER_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_SSH_MANAGER_H

#include "Definitions/Definitions.h"
#include "Ssh/SshManager.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// Script-facing convenience facade over CSshManager -- same treatment as CScriptCertificateManager
// (see its own header comment): every raw buffer method gets a std::string counterpart that does
// the buffer marshaling internally and throws CScriptException instead of returning an ErrorCode.
//
// Two deliberate simplifications versus CSshManager's own C++ signature, both scoped to this
// script-facing layer only (matching CScriptCertificateManager's own precedent of documenting
// exactly this kind of simplification):
// 1. Connect() returns a plain bool (true on success) instead of throwing on failure -- unlike
//    every other method here, "the server isn't reachable" is an ordinary, expected outcome for a
//    script that wants to probe before doing anything else (mirrors CScriptPgpEngineWrapper's own
//    non-throwing IsGnuPgAvailable()), not a hard script error. Every method below Connect() DOES
//    throw on failure, since by that point a real session is assumed to exist.
// 2. ExecuteCommand() returns only stdout text (the primary output); stderr text and the remote
//    exit status are stashed and retrieved via GetLastExecStderr()/GetLastExecExitStatus() below,
//    same "stash the secondary output" convention CScriptCertificateManager's own
//    CreateSelfSignedCertificate/CreateCertificateRequest use for the generated private key.
//
// SshHostKeyCheckResult values are passed/returned as plain int here (0=Match, 1=Mismatch,
// 2=NotFound, 3=CheckFailed -- see ISshManager.h) for the same reason CScriptCertificateManager's
// own header comment explains for its own four enums: not worth registering as a real script enum
// type in 5 different engines for one small value set.
class CScriptSshManager
{
public:
    virtual ~CScriptSshManager();
             CScriptSshManager();

    // ============================================================================================
    // Connection lifecycle -- see ISshManager.h for full documentation of each underlying method.
    // ============================================================================================

    bool Connect(const std::string& host, const int port, const int timeoutMs);
    void Disconnect(void);
    bool IsConnected(void) const;

    // ============================================================================================
    // Host key verification
    // ============================================================================================

    std::string GetHostKeyFingerprint(void) const;

    // Returns the SshHostKeyCheckResult value as plain int (see this class's own header comment).
    int CheckKnownHost(const std::string& knownHostsFilePath);

    void AddKnownHost(const std::string& knownHostsFilePath, const std::string& hostNameForEntry);

    // ============================================================================================
    // User authentication
    // ============================================================================================

    void AuthenticatePassword(const std::string& username, const std::string& password);

    void AuthenticatePublicKey( const std::string& username, const std::string& publicKeyFilePath,
                               const std::string& privateKeyFilePath, const std::string& passphrase);

    bool IsAuthenticated(void) const;

    // ============================================================================================
    // Command execution -- see this class's own header comment for the stash convention.
    // ============================================================================================

    std::string ExecuteCommand(const std::string& command);
    std::string GetLastExecStderr(void) const;
    int GetLastExecExitStatus(void) const;

    // ============================================================================================
    // SFTP
    // ============================================================================================

    void SftpUploadFile(const std::string& localFilePath, const std::string& remoteFilePath);
    void SftpDownloadFile(const std::string& remoteFilePath, const std::string& localFilePath);

    std::string GetLastErrorMessage(void) const;

protected:

private:

    // Same two-call capacity-query dance as CScriptCertificateManager's own private helper.
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;
    void callVoid(const char* methodName, const std::function<int(void)>& fn);

    CSshManager engine_;
    std::string lastExecStderr_;
    int lastExecExitStatus_;

};

} // namespace CryptoApiNS

#endif

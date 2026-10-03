#ifndef CRYPTOAPI_ISSH_MANAGER_H
#define CRYPTOAPI_ISSH_MANAGER_H

#include "Definitions/Definitions.h"

namespace CryptoApiNS
{

// CheckKnownHost's *result out-parameter -- mirrors real OpenSSH's own three-way known_hosts
// verdict (libssh2_knownhost_check's own LIBSSH2_KNOWNHOST_CHECK_* codes, which this engine
// delegates to directly rather than reimplementing known_hosts parsing). SSH_HOST_KEY_CHECK_FAILED
// is this engine's own addition for "could not even read/parse the known_hosts file" (a distinct
// failure from "host simply isn't in it yet").
enum SshHostKeyCheckResult
{
    SSH_HOST_KEY_MATCH        = 0,
    SSH_HOST_KEY_MISMATCH     = 1,
    SSH_HOST_KEY_NOT_FOUND    = 2,
    SSH_HOST_KEY_CHECK_FAILED = 3
};

// Pure-virtual mirror of CSshManager's instance methods (see Ssh/SshManager.h for full
// documentation of each method -- not repeated here to avoid drift between the two). Exists for
// the same DLL-boundary reason ICertificateManager.h/IPgpEngine.h do -- CSshManager's default
// constructor is the only one reachable through CreateSshManager() (see CryptoApiFactory.h).
// Standalone (Plan.md §27.1 "SSH, TLS'den bağımsız protokol ve güven modelidir" -- not routed
// through ICryptoProvider/IAeadCipher/etc., matching CPgpEngine's own precedent of being its own
// top-level engine rather than a provider-backed service).
class ISshManager
{
public:
    virtual ~ISshManager();
             ISshManager();

    // ============================================================================================
    // Connection lifecycle. One instance = one session, matching libssh2's own LIBSSH2_SESSION
    // lifetime (Plan.md §27.2's SshSession) -- Connect() must succeed before any authentication/
    // channel/SFTP method below; Disconnect() (also called by the destructor on a best-effort
    // basis) tears everything down and lets Connect() be called again on the same instance.
    // ============================================================================================

    // Opens the TCP connection and performs the SSH2 key exchange (Plan.md §27.5's Connecting ->
    // KeyExchange -> HostVerified). Does NOT authenticate -- see AuthenticatePassword/
    // AuthenticatePublicKey below, matching real SSH's own "host key verified before credentials
    // are sent" ordering (Plan.md §27.3). timeoutMs applies to both the TCP connect and the SSH
    // handshake; 0 means libssh2's own default (blocking, no explicit timeout).
    virtual int Connect(const char* host, const int hostSize, const unsigned short port, const unsigned int timeoutMs) = 0;

    virtual int Disconnect(void) = 0;

    virtual bool IsConnected(void) const = 0;

    // ============================================================================================
    // Host key verification (Plan.md §27.3) -- GetHostKeyFingerprint lets a caller verify the
    // server's identity out-of-band (e.g. compare against a value communicated through a separate
    // channel); CheckKnownHost/AddKnownHost delegate to libssh2's own real OpenSSH-format
    // known_hosts parser/writer (libssh2_knownhost_*) rather than a reimplementation, so the same
    // file an actual `ssh`/`sftp` client reads or writes can be shared with this engine.
    // ============================================================================================

    // SHA-256 fingerprint of the connected server's host key, lowercase hex (no colons, no
    // "SHA256:" prefix, no base64 -- a fixed, unambiguous textual form a caller can compare
    // byte-for-byte; outputBufferCapacity must be >= 65). Connect() must have succeeded first.
    virtual int GetHostKeyFingerprint(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const = 0;

    // Checks the connected server's host key against knownHostsFilePath (OpenSSH known_hosts
    // format, e.g. "%USERPROFILE%\.ssh\known_hosts"). Connect() must have succeeded first.
    virtual int CheckKnownHost(const char* knownHostsFilePath, const int knownHostsFilePathSize, SshHostKeyCheckResult* result) = 0;

    // Appends (or updates, if an entry for hostNameForEntry already exists) the connected server's
    // host key in knownHostsFilePath -- the deliberate, explicit "pin now" action Plan.md §27.3's
    // "sessiz accept-all yoktur" rule requires (no implicit trust-on-first-use inside Connect()
    // itself). hostNameForEntry is the hostname:port text written into the known_hosts line (may
    // differ from Connect()'s own host parameter, e.g. to record under a different alias).
    virtual int AddKnownHost( const char* knownHostsFilePath, const int knownHostsFilePathSize,
                             const char* hostNameForEntry, const int hostNameForEntrySize) = 0;

    // ============================================================================================
    // User authentication (Plan.md §27.3) -- Connect() must have succeeded first. Exactly one of
    // these needs to succeed before ExecuteCommand/SftpUploadFile/SftpDownloadFile below.
    // ============================================================================================

    virtual int AuthenticatePassword( const char* username, const int usernameSize,
                                      const char* password, const int passwordSize) = 0;

    // publicKeyFilePath/privateKeyFilePath are OpenSSH-format key files on local disk (the same
    // files `ssh`/`ssh-keygen` produce) -- no in-memory key buffer overload in v1 scope.
    // passphrase may be nullptr/0-length for an unencrypted private key.
    virtual int AuthenticatePublicKey( const char* username, const int usernameSize,
                                       const char* publicKeyFilePath, const int publicKeyFilePathSize,
                                       const char* privateKeyFilePath, const int privateKeyFilePathSize,
                                       const char* passphrase, const int passphraseSize) = 0;

    virtual bool IsAuthenticated(void) const = 0;

    // ============================================================================================
    // Command execution (Plan.md §27.4) -- a single blocking SSH "exec" channel request, v1 scope
    // (no PTY/shell, no streaming -- matches Plan.md §27.4's own "automatik tekrar çalıştırılmaz"
    // single-shot model). Authentication must have succeeded first.
    // ============================================================================================

    // stdout and stderr are captured into two separate buffers (Plan.md §27.4's "stdout ve stderr
    // birlikte boşaltılır" rule -- this engine drains both internally so a caller can never
    // deadlock by only reading one). exitStatus is the remote command's real exit code; -1 if the
    // channel closed without ever reporting one (Plan.md §27.4's "eksik exit status sıfır olarak
    // uydurulmaz").
    virtual int ExecuteCommand( const char* command, const int commandSize,
                                const int stdoutCapacity, char* stdoutBuffer, int* stdoutSize,
                                const int stderrCapacity, char* stderrBuffer, int* stderrSize,
                                int* exitStatus) = 0;

    // ============================================================================================
    // SFTP (Plan.md §27.4's "ilk dosya aktarım yöntemi") -- single whole-file transfer, v1 scope
    // (no byte/stream adaptors, no recursive folder transfer, no resume). Authentication must have
    // succeeded first.
    // ============================================================================================

    virtual int SftpUploadFile( const char* localFilePath, const int localFilePathSize,
                               const char* remoteFilePath, const int remoteFilePathSize) = 0;

    virtual int SftpDownloadFile( const char* remoteFilePath, const int remoteFilePathSize,
                                 const char* localFilePath, const int localFilePathSize) = 0;

    // Human-readable text of the last libssh2 error this instance encountered (libssh2's own
    // libssh2_session_last_error message) -- empty string if none yet.
    virtual int GetLastErrorMessage(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const = 0;
};

} // namespace CryptoApiNS

#endif

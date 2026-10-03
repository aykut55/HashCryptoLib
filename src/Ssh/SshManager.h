#ifndef AYCRYPTO_SSH_MANAGER_H
#define AYCRYPTO_SSH_MANAGER_H

#include "Definitions/Definitions.h"
#include "Interfaces/ISshManager.h"

#include <memory>

// Same DLL export/import boundary reasoning as Pgp/PgpEngine.h's own identical block.
#if defined(CRYPTOAPI_DLL_EXPORTS)
#define CRYPTOAPI_API __declspec(dllexport)
#elif defined(CRYPTOAPI_DLL_IMPORTS)
#define CRYPTOAPI_API __declspec(dllimport)
#else
#define CRYPTOAPI_API
#endif

namespace CryptoApiNS
{

// C4251/C4275: see CryptoApi.h's own identical pragma block -- impl_ is private and never touched
// across the DLL boundary, and ISshManager (this class's base) declares no data and no non-inline
// code of its own.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4251)
#pragma warning(disable: 4275)
#endif

// SSH2 client session (libssh2-backed, OpenSSL crypto backend -- reuses this repo's existing
// 3rdParty/openssl402, no new crypto dependency). One flat facade class, same real precedent
// CCryptoApi/CPgpEngine/CCertificateManager all actually collapsed to -- Plan.md §27.2's
// fine-grained SshService/SshClient/SshSession/SshChannel/SftpClient class table was never built
// as separate classes anywhere in this codebase. Deliberately standalone: NOT routed through
// ICryptoProvider/IAeadCipher/etc. (Plan.md §27.1 "SSH, TLS'den bağımsız protokol ve güven
// modelidir" -- this is a different trust model from the certificate/PKI-based ones the provider
// abstraction was built around).
class CRYPTOAPI_API CSshManager : public ISshManager
{
public:
    virtual ~CSshManager();
             CSshManager();

    // ============================================================================================
    // Connection lifecycle -- see ISshManager.h for full documentation of each method.
    // ============================================================================================

    int Connect(const char* host, const int hostSize, const unsigned short port, const unsigned int timeoutMs) override;

    int Disconnect(void) override;

    bool IsConnected(void) const override;

    // ============================================================================================
    // Host key verification
    // ============================================================================================

    int GetHostKeyFingerprint(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const override;

    int CheckKnownHost(const char* knownHostsFilePath, const int knownHostsFilePathSize, SshHostKeyCheckResult* result) override;

    int AddKnownHost( const char* knownHostsFilePath, const int knownHostsFilePathSize,
                     const char* hostNameForEntry, const int hostNameForEntrySize) override;

    // ============================================================================================
    // User authentication
    // ============================================================================================

    int AuthenticatePassword( const char* username, const int usernameSize,
                              const char* password, const int passwordSize) override;

    int AuthenticatePublicKey( const char* username, const int usernameSize,
                               const char* publicKeyFilePath, const int publicKeyFilePathSize,
                               const char* privateKeyFilePath, const int privateKeyFilePathSize,
                               const char* passphrase, const int passphraseSize) override;

    bool IsAuthenticated(void) const override;

    // ============================================================================================
    // Command execution
    // ============================================================================================

    int ExecuteCommand( const char* command, const int commandSize,
                        const int stdoutCapacity, char* stdoutBuffer, int* stdoutSize,
                        const int stderrCapacity, char* stderrBuffer, int* stderrSize,
                        int* exitStatus) override;

    // ============================================================================================
    // SFTP
    // ============================================================================================

    int SftpUploadFile( const char* localFilePath, const int localFilePathSize,
                       const char* remoteFilePath, const int remoteFilePathSize) override;

    int SftpDownloadFile( const char* remoteFilePath, const int remoteFilePathSize,
                         const char* localFilePath, const int localFilePathSize) override;

    int GetLastErrorMessage(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const override;

protected:

private:

    // libssh2/Winsock types are kept out of this header so callers never need those headers or
    // include paths; only SshManager.cpp does (same pattern as CPgpEngine's own CryptoPP-hiding
    // Impl, CCertificateManager's own OpenSSL/Crypt32-hiding Impl).
    struct Impl;
    std::unique_ptr<Impl> impl_;

};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace CryptoApiNS

#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
// winsock2.h must be included before libssh2.h (libssh2.h itself #includes <winsock2.h> again
// under an "#ifdef _WIN32" guard with its own include-guard, but every libssh2 example does this
// same explicit include first -- matching that convention rather than relying on the transitive
// include).
// libssh2.h's own LIBSSH2_API macro defaults to __declspec(dllimport) whenever _WINDLL is defined
// (MSVC defines _WINDLL automatically for every DLL project, e.g. DllBuilder here) -- that assumes
// libssh2 itself is built as a DLL with a matching import library, which Ssh2.vcxproj deliberately
// is NOT (a plain static library, same as every other 3rdParty dependency in this repo). Pre-empting
// libssh2.h's own "#ifndef LIBSSH2_API" guard here keeps every libssh2_* symbol a plain (non-
// dllimport) external, resolvable against Ssh2.lib regardless of which project compiles this file.
#define LIBSSH2_API
#include "libssh2.h"
#include "libssh2_sftp.h"
// winsock2.h (via WinError.h) #defines NO_ERROR to 0L, which collides with CryptoApiNS's own
// ErrorCode::NO_ERROR enumerator (Definitions.h) once SshManager.h is included below -- same
// guarded #undef pattern CryptoApiDllLoader.h/CryptoApi.cpp already use for this exact collision.
#ifdef NO_ERROR
#undef NO_ERROR
#endif

#include "SshManager.h"

#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")

namespace CryptoApiNS
{

namespace
{

// libssh2_init(0)/WSAStartup are both process-wide, idempotent-unsafe-to-call-concurrently
// one-time setup calls -- std::call_once guards each so multiple CSshManager instances (and
// multiple threads constructing them) never race. Neither is ever torn down explicitly
// (libssh2_exit()/WSACleanup() are deliberately not called) since a later CSshManager instance in
// the same process could still need them; this matches the already-established pattern elsewhere
// in this codebase of not tearing down process-wide crypto library state on a per-instance basis.
std::once_flag g_sshGlobalInitOnce;

void ensureGlobalInit(void)
{
    std::call_once(g_sshGlobalInitOnce, []()
    {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        libssh2_init(0);
    });
}
// -----------------------------------------------------------------------------

std::string hexEncode(const unsigned char* data, const std::size_t size)
{
    static const char hexDigits[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i)
    {
        result.push_back(hexDigits[(data[i] >> 4) & 0x0F]);
        result.push_back(hexDigits[data[i] & 0x0F]);
    }
    return result;
}
// -----------------------------------------------------------------------------

// Maps libssh2_session_hostkey's own LIBSSH2_HOSTKEY_TYPE_* out-parameter to the (differently
// numbered) LIBSSH2_KNOWNHOST_KEY_* bits libssh2_knownhost_addc/checkp's typemask expects --
// these are NOT the same numeric values (verified by reading libssh2.h directly), so a lookup is
// required rather than a direct cast.
int hostkeyTypeToKnownhostKeyBits(const int hostkeyType)
{
    switch (hostkeyType)
    {
        case LIBSSH2_HOSTKEY_TYPE_RSA:        return LIBSSH2_KNOWNHOST_KEY_SSHRSA;
        case LIBSSH2_HOSTKEY_TYPE_DSS:        return LIBSSH2_KNOWNHOST_KEY_SSHDSS;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:  return LIBSSH2_KNOWNHOST_KEY_ECDSA_256;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:  return LIBSSH2_KNOWNHOST_KEY_ECDSA_384;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:  return LIBSSH2_KNOWNHOST_KEY_ECDSA_521;
        case LIBSSH2_HOSTKEY_TYPE_ED25519:    return LIBSSH2_KNOWNHOST_KEY_ED25519;
        default:                              return LIBSSH2_KNOWNHOST_KEY_UNKNOWN;
    }
}
// -----------------------------------------------------------------------------

// Standard capacity-query convention (same as CPgpEngine::ExportPublicKeyArmored,
// CCertificateManager::GetCertificateInfoText, etc.): outputBuffer==nullptr or
// outputBufferCapacity too small -> BUFFER_TOO_SMALL with the required size in *outputBufferSize;
// otherwise copies text into outputBuffer and returns NO_ERROR.
int copyTextToOutputBuffer(const std::string& text, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    if (outputBufferSize == nullptr)
    {
        return INVALID_ARGUMENT;
    }
    if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(text.size()))
    {
        *outputBufferSize = static_cast<int>(text.size());
        return BUFFER_TOO_SMALL;
    }
    if (!text.empty())
    {
        std::memcpy(outputBuffer, text.data(), text.size());
    }
    *outputBufferSize = static_cast<int>(text.size());
    return NO_ERROR;
}
// -----------------------------------------------------------------------------

} // anonymous namespace

// ================================================================================================
// Impl -- kept out of the header so callers never need libssh2's own headers or Winsock, same
// pattern as CPgpEngine's CryptoPP-hiding Impl / CCertificateManager's OpenSSL-hiding Impl.
// ================================================================================================

struct CSshManager::Impl
{
    SOCKET socketHandle;
    LIBSSH2_SESSION* session;
    bool connected;
    bool authenticated;
    std::string connectedHost;
    unsigned short connectedPort;
    std::string lastErrorText;

    Impl() : socketHandle(INVALID_SOCKET), session(nullptr), connected(false), authenticated(false), connectedPort(0)
    {
    }

    ~Impl()
    {
        disconnectInternal();
    }

    // Pulls libssh2's own last-error text for this session (its own internal buffer, not owned by
    // the caller) into lastErrorText before it is at risk of being overwritten by the next libssh2
    // call -- callers of GetLastErrorMessage() read lastErrorText, never libssh2 directly.
    void captureLastError(void)
    {
        if (session == nullptr)
        {
            return;
        }
        char* errorMessage = nullptr;
        int errorMessageLength = 0;
        libssh2_session_last_error(session, &errorMessage, &errorMessageLength, 0);
        if (errorMessage != nullptr && errorMessageLength > 0)
        {
            lastErrorText.assign(errorMessage, static_cast<std::size_t>(errorMessageLength));
        }
    }

    void disconnectInternal(void)
    {
        if (session != nullptr)
        {
            libssh2_session_disconnect(session, "CSshManager disconnect");
            libssh2_session_free(session);
            session = nullptr;
        }
        if (socketHandle != INVALID_SOCKET)
        {
            closesocket(socketHandle);
            socketHandle = INVALID_SOCKET;
        }
        connected = false;
        authenticated = false;
    }
};
// -----------------------------------------------------------------------------

CSshManager::CSshManager() : impl_(new Impl())
{
    ensureGlobalInit();
}
// -----------------------------------------------------------------------------

CSshManager::~CSshManager()
{
}
// -----------------------------------------------------------------------------

int CSshManager::Connect(const char* host, const int hostSize, const unsigned short port, const unsigned int timeoutMs)
{
    try
    {
        if (!impl_ || host == nullptr || hostSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (impl_->connected)
        {
            return INVALID_ARGUMENT;
        }

        const std::string hostStr(host, static_cast<std::size_t>(hostSize));

        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        char portStr[16];
        std::snprintf(portStr, sizeof(portStr), "%u", static_cast<unsigned int>(port));

        struct addrinfo* resolved = nullptr;
        if (getaddrinfo(hostStr.c_str(), portStr, &hints, &resolved) != 0 || resolved == nullptr)
        {
            return UNEXPECTED_ERROR;
        }

        SOCKET sock = INVALID_SOCKET;
        for (struct addrinfo* candidate = resolved; candidate != nullptr; candidate = candidate->ai_next)
        {
            sock = socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
            if (sock == INVALID_SOCKET)
            {
                continue;
            }

            // Non-blocking connect + select-for-writable-with-timeout, then back to blocking --
            // plain blocking connect() has no portable per-call timeout on Windows otherwise.
            // timeoutMs == 0 means "libssh2's own default", here treated as a generous fixed
            // fallback rather than an unbounded blocking connect.
            u_long nonBlocking = 1;
            ioctlsocket(sock, FIONBIO, &nonBlocking);

            const int connectResult = connect(sock, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen));
            bool connectSucceeded = (connectResult == 0);
            if (!connectSucceeded && WSAGetLastError() == WSAEWOULDBLOCK)
            {
                fd_set writeSet;
                FD_ZERO(&writeSet);
                FD_SET(sock, &writeSet);
                struct timeval tv;
                const unsigned int effectiveTimeoutMs = (timeoutMs > 0) ? timeoutMs : 30000u;
                tv.tv_sec = static_cast<long>(effectiveTimeoutMs / 1000u);
                tv.tv_usec = static_cast<long>((effectiveTimeoutMs % 1000u) * 1000u);
                const int selectResult = select(0, nullptr, &writeSet, nullptr, &tv);
                connectSucceeded = (selectResult == 1) && FD_ISSET(sock, &writeSet);
            }

            u_long blocking = 0;
            ioctlsocket(sock, FIONBIO, &blocking);

            if (connectSucceeded)
            {
                break;
            }
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        freeaddrinfo(resolved);

        if (sock == INVALID_SOCKET)
        {
            return UNEXPECTED_ERROR;
        }

        LIBSSH2_SESSION* session = libssh2_session_init();
        if (session == nullptr)
        {
            closesocket(sock);
            return UNEXPECTED_ERROR;
        }
        libssh2_session_set_blocking(session, 1);

        if (libssh2_session_handshake(session, sock) != 0)
        {
            libssh2_session_free(session);
            closesocket(sock);
            return UNEXPECTED_ERROR;
        }

        impl_->socketHandle = sock;
        impl_->session = session;
        impl_->connected = true;
        impl_->authenticated = false;
        impl_->connectedHost = hostStr;
        impl_->connectedPort = port;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CSshManager::Disconnect(void)
{
    try
    {
        if (!impl_)
        {
            return INVALID_ARGUMENT;
        }
        impl_->disconnectInternal();
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

bool CSshManager::IsConnected(void) const
{
    return impl_ && impl_->connected;
}
// -----------------------------------------------------------------------------

int CSshManager::GetHostKeyFingerprint(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const
{
    try
    {
        if (!impl_ || !impl_->connected || impl_->session == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        const char* rawHash = libssh2_hostkey_hash(impl_->session, LIBSSH2_HOSTKEY_HASH_SHA256);
        if (rawHash == nullptr)
        {
            return UNEXPECTED_ERROR;
        }
        const std::string hex = hexEncode(reinterpret_cast<const unsigned char*>(rawHash), 32);
        return copyTextToOutputBuffer(hex, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CSshManager::CheckKnownHost(const char* knownHostsFilePath, const int knownHostsFilePathSize, SshHostKeyCheckResult* result)
{
    try
    {
        if (!impl_ || !impl_->connected || impl_->session == nullptr ||
            knownHostsFilePath == nullptr || knownHostsFilePathSize <= 0 || result == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        const std::string path(knownHostsFilePath, static_cast<std::size_t>(knownHostsFilePathSize));

        size_t hostKeyLength = 0;
        int hostKeyType = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
        const char* hostKey = libssh2_session_hostkey(impl_->session, &hostKeyLength, &hostKeyType);
        if (hostKey == nullptr)
        {
            return UNEXPECTED_ERROR;
        }

        LIBSSH2_KNOWNHOSTS* knownHosts = libssh2_knownhost_init(impl_->session);
        if (knownHosts == nullptr)
        {
            return UNEXPECTED_ERROR;
        }
        // A missing/empty known_hosts file is not itself an error here -- the check below then
        // naturally reports SSH_HOST_KEY_NOT_FOUND, matching real OpenSSH's own first-connection
        // behavior rather than failing outright.
        libssh2_knownhost_readfile(knownHosts, path.c_str(), LIBSSH2_KNOWNHOST_FILE_OPENSSH);

        const int typeMask = LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | hostkeyTypeToKnownhostKeyBits(hostKeyType);
        struct libssh2_knownhost* matchedEntry = nullptr;
        const int checkResult = libssh2_knownhost_checkp( knownHosts, impl_->connectedHost.c_str(), static_cast<int>(impl_->connectedPort),
                                                          hostKey, hostKeyLength, typeMask, &matchedEntry);
        libssh2_knownhost_free(knownHosts);

        switch (checkResult)
        {
            case LIBSSH2_KNOWNHOST_CHECK_MATCH:    *result = SSH_HOST_KEY_MATCH;        break;
            case LIBSSH2_KNOWNHOST_CHECK_MISMATCH: *result = SSH_HOST_KEY_MISMATCH;     break;
            case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND: *result = SSH_HOST_KEY_NOT_FOUND;    break;
            default:                               *result = SSH_HOST_KEY_CHECK_FAILED; break;
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CSshManager::AddKnownHost( const char* knownHostsFilePath, const int knownHostsFilePathSize,
                              const char* hostNameForEntry, const int hostNameForEntrySize)
{
    try
    {
        if (!impl_ || !impl_->connected || impl_->session == nullptr ||
            knownHostsFilePath == nullptr || knownHostsFilePathSize <= 0 ||
            hostNameForEntry == nullptr || hostNameForEntrySize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        const std::string path(knownHostsFilePath, static_cast<std::size_t>(knownHostsFilePathSize));
        const std::string entryHost(hostNameForEntry, static_cast<std::size_t>(hostNameForEntrySize));

        size_t hostKeyLength = 0;
        int hostKeyType = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
        const char* hostKey = libssh2_session_hostkey(impl_->session, &hostKeyLength, &hostKeyType);
        if (hostKey == nullptr)
        {
            return UNEXPECTED_ERROR;
        }

        LIBSSH2_KNOWNHOSTS* knownHosts = libssh2_knownhost_init(impl_->session);
        if (knownHosts == nullptr)
        {
            return UNEXPECTED_ERROR;
        }
        // Read whatever already exists first (ignored if the file does not exist yet) so this
        // becomes an append/update, not a destructive overwrite of every other host's entry.
        libssh2_knownhost_readfile(knownHosts, path.c_str(), LIBSSH2_KNOWNHOST_FILE_OPENSSH);

        const int typeMask = LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | hostkeyTypeToKnownhostKeyBits(hostKeyType);
        const int addResult = libssh2_knownhost_addc( knownHosts, entryHost.c_str(), nullptr,
                                                      hostKey, hostKeyLength, nullptr, 0, typeMask, nullptr);
        if (addResult != 0)
        {
            libssh2_knownhost_free(knownHosts);
            return UNEXPECTED_ERROR;
        }

        const int writeResult = libssh2_knownhost_writefile(knownHosts, path.c_str(), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
        libssh2_knownhost_free(knownHosts);
        if (writeResult != 0)
        {
            return FILE_IO_ERROR;
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CSshManager::AuthenticatePassword( const char* username, const int usernameSize,
                                      const char* password, const int passwordSize)
{
    try
    {
        if (!impl_ || !impl_->connected || impl_->session == nullptr ||
            username == nullptr || usernameSize <= 0 || password == nullptr || passwordSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        const int status = libssh2_userauth_password_ex( impl_->session, username, static_cast<unsigned int>(usernameSize),
                                                         password, static_cast<unsigned int>(passwordSize), nullptr);
        if (status != 0)
        {
            impl_->captureLastError();
            return UNEXPECTED_ERROR;
        }
        impl_->authenticated = (libssh2_userauth_authenticated(impl_->session) != 0);
        return impl_->authenticated ? NO_ERROR : UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CSshManager::AuthenticatePublicKey( const char* username, const int usernameSize,
                                       const char* publicKeyFilePath, const int publicKeyFilePathSize,
                                       const char* privateKeyFilePath, const int privateKeyFilePathSize,
                                       const char* passphrase, const int passphraseSize)
{
    try
    {
        if (!impl_ || !impl_->connected || impl_->session == nullptr ||
            username == nullptr || usernameSize <= 0 ||
            privateKeyFilePath == nullptr || privateKeyFilePathSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        const std::string usernameStr(username, static_cast<std::size_t>(usernameSize));
        const std::string publicKeyPath = (publicKeyFilePath != nullptr && publicKeyFilePathSize > 0)
            ? std::string(publicKeyFilePath, static_cast<std::size_t>(publicKeyFilePathSize)) : std::string();
        const std::string privateKeyPath(privateKeyFilePath, static_cast<std::size_t>(privateKeyFilePathSize));
        const std::string passphraseStr = (passphrase != nullptr && passphraseSize > 0)
            ? std::string(passphrase, static_cast<std::size_t>(passphraseSize)) : std::string();

        const int status = libssh2_userauth_publickey_fromfile_ex( impl_->session, usernameStr.c_str(), static_cast<unsigned int>(usernameStr.size()),
                                                                    publicKeyPath.empty() ? nullptr : publicKeyPath.c_str(),
                                                                    privateKeyPath.c_str(),
                                                                    passphraseStr.empty() ? nullptr : passphraseStr.c_str());
        if (status != 0)
        {
            impl_->captureLastError();
            return UNEXPECTED_ERROR;
        }
        impl_->authenticated = (libssh2_userauth_authenticated(impl_->session) != 0);
        return impl_->authenticated ? NO_ERROR : UNEXPECTED_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

bool CSshManager::IsAuthenticated(void) const
{
    return impl_ && impl_->authenticated;
}
// -----------------------------------------------------------------------------

int CSshManager::ExecuteCommand( const char* command, const int commandSize,
                                const int stdoutCapacity, char* stdoutBuffer, int* stdoutSize,
                                const int stderrCapacity, char* stderrBuffer, int* stderrSize,
                                int* exitStatus)
{
    try
    {
        if (!impl_ || !impl_->connected || !impl_->authenticated || impl_->session == nullptr ||
            command == nullptr || commandSize <= 0 || stdoutSize == nullptr || stderrSize == nullptr || exitStatus == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        const std::string commandStr(command, static_cast<std::size_t>(commandSize));

        LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(impl_->session);
        if (channel == nullptr)
        {
            impl_->captureLastError();
            return UNEXPECTED_ERROR;
        }
        if (libssh2_channel_exec(channel, commandStr.c_str()) != 0)
        {
            impl_->captureLastError();
            libssh2_channel_free(channel);
            return UNEXPECTED_ERROR;
        }

        std::string collectedStdout;
        std::string collectedStderr;
        char readBuffer[4096];
        ssize_t bytesRead = 0;
        while ((bytesRead = libssh2_channel_read(channel, readBuffer, sizeof(readBuffer))) > 0)
        {
            collectedStdout.append(readBuffer, static_cast<std::size_t>(bytesRead));
        }
        while ((bytesRead = libssh2_channel_read_stderr(channel, readBuffer, sizeof(readBuffer))) > 0)
        {
            collectedStderr.append(readBuffer, static_cast<std::size_t>(bytesRead));
        }

        libssh2_channel_send_eof(channel);
        libssh2_channel_wait_eof(channel);
        libssh2_channel_close(channel);
        libssh2_channel_wait_closed(channel);
        *exitStatus = libssh2_channel_get_exit_status(channel);
        libssh2_channel_free(channel);

        const int stdoutStatus = copyTextToOutputBuffer(collectedStdout, stdoutCapacity, stdoutBuffer, stdoutSize);
        const int stderrStatus = copyTextToOutputBuffer(collectedStderr, stderrCapacity, stderrBuffer, stderrSize);
        if (stdoutStatus != NO_ERROR)
        {
            return stdoutStatus;
        }
        if (stderrStatus != NO_ERROR)
        {
            return stderrStatus;
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CSshManager::SftpUploadFile( const char* localFilePath, const int localFilePathSize,
                                const char* remoteFilePath, const int remoteFilePathSize)
{
    try
    {
        if (!impl_ || !impl_->connected || !impl_->authenticated || impl_->session == nullptr ||
            localFilePath == nullptr || localFilePathSize <= 0 || remoteFilePath == nullptr || remoteFilePathSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        const std::string localPath(localFilePath, static_cast<std::size_t>(localFilePathSize));
        const std::string remotePath(remoteFilePath, static_cast<std::size_t>(remoteFilePathSize));

        std::ifstream localStream(localPath, std::ios::binary);
        if (!localStream.is_open())
        {
            return FILE_IO_ERROR;
        }

        LIBSSH2_SFTP* sftp = libssh2_sftp_init(impl_->session);
        if (sftp == nullptr)
        {
            impl_->captureLastError();
            return UNEXPECTED_ERROR;
        }
        LIBSSH2_SFTP_HANDLE* remoteHandle = libssh2_sftp_open( sftp, remotePath.c_str(),
                                                               LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
                                                               LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH);
        if (remoteHandle == nullptr)
        {
            impl_->captureLastError();
            libssh2_sftp_shutdown(sftp);
            return UNEXPECTED_ERROR;
        }

        char chunkBuffer[8192];
        bool ioFailed = false;
        while (localStream.read(chunkBuffer, sizeof(chunkBuffer)) || localStream.gcount() > 0)
        {
            const std::streamsize readCount = localStream.gcount();
            std::size_t writtenSoFar = 0;
            while (writtenSoFar < static_cast<std::size_t>(readCount))
            {
                const ssize_t written = libssh2_sftp_write(remoteHandle, chunkBuffer + writtenSoFar, static_cast<std::size_t>(readCount) - writtenSoFar);
                if (written < 0)
                {
                    ioFailed = true;
                    break;
                }
                writtenSoFar += static_cast<std::size_t>(written);
            }
            if (ioFailed)
            {
                break;
            }
        }

        libssh2_sftp_close_handle(remoteHandle);
        libssh2_sftp_shutdown(sftp);
        return ioFailed ? UNEXPECTED_ERROR : NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CSshManager::SftpDownloadFile( const char* remoteFilePath, const int remoteFilePathSize,
                                  const char* localFilePath, const int localFilePathSize)
{
    try
    {
        if (!impl_ || !impl_->connected || !impl_->authenticated || impl_->session == nullptr ||
            remoteFilePath == nullptr || remoteFilePathSize <= 0 || localFilePath == nullptr || localFilePathSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        const std::string remotePath(remoteFilePath, static_cast<std::size_t>(remoteFilePathSize));
        const std::string localPath(localFilePath, static_cast<std::size_t>(localFilePathSize));

        LIBSSH2_SFTP* sftp = libssh2_sftp_init(impl_->session);
        if (sftp == nullptr)
        {
            impl_->captureLastError();
            return UNEXPECTED_ERROR;
        }
        LIBSSH2_SFTP_HANDLE* remoteHandle = libssh2_sftp_open(sftp, remotePath.c_str(), LIBSSH2_FXF_READ, 0);
        if (remoteHandle == nullptr)
        {
            impl_->captureLastError();
            libssh2_sftp_shutdown(sftp);
            return UNEXPECTED_ERROR;
        }

        std::ofstream localStream(localPath, std::ios::binary | std::ios::trunc);
        if (!localStream.is_open())
        {
            libssh2_sftp_close_handle(remoteHandle);
            libssh2_sftp_shutdown(sftp);
            return FILE_IO_ERROR;
        }

        char chunkBuffer[8192];
        bool ioFailed = false;
        ssize_t bytesRead = 0;
        while ((bytesRead = libssh2_sftp_read(remoteHandle, chunkBuffer, sizeof(chunkBuffer))) > 0)
        {
            localStream.write(chunkBuffer, bytesRead);
            if (!localStream)
            {
                ioFailed = true;
                break;
            }
        }
        if (bytesRead < 0)
        {
            ioFailed = true;
        }

        localStream.close();
        libssh2_sftp_close_handle(remoteHandle);
        libssh2_sftp_shutdown(sftp);
        return ioFailed ? UNEXPECTED_ERROR : NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CSshManager::GetLastErrorMessage(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const
{
    try
    {
        if (!impl_)
        {
            return INVALID_ARGUMENT;
        }
        return copyTextToOutputBuffer(impl_->lastErrorText, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

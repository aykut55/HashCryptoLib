#include "PgpEngineWrapper.h"
#include "Definitions/Definitions.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace CryptoApiNS
{

namespace
{

// ================================================================================================
// gpg.exe discovery -- reimplemented here (not shared with CryptoApiTester.cpp's own
// FindGpgExecutable) since this is product code and must not depend on test-file internals. Same
// two well-known Gpg4win install paths.
// ================================================================================================

std::string findGpgExecutableForWrapper(void)
{
    static const char* candidates[] =
    {
        "C:\\Program Files\\GnuPG\\bin\\gpg.exe",
        "C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe"
    };
    for (std::size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i)
    {
        std::ifstream probe(candidates[i], std::ios::binary);
        if (probe.good())
        {
            return candidates[i];
        }
    }
    return std::string();
}
// -----------------------------------------------------------------------------

// ================================================================================================
// UTF-8 <-> UTF-16 conversion. Command-line arguments and file paths this class deals with are
// UTF-8 (Rules.md convention); CreateProcessW/Win32 need UTF-16.
// ================================================================================================

bool utf8ToWide(const std::string& utf8Text, std::wstring& wideTextOut)
{
    try
    {
        if (utf8Text.empty())
        {
            wideTextOut.clear();
            return true;
        }
        const int wideSize = MultiByteToWideChar(CP_UTF8, 0, utf8Text.c_str(), static_cast<int>(utf8Text.size()), nullptr, 0);
        if (wideSize <= 0)
        {
            return false;
        }
        std::vector<wchar_t> buffer(static_cast<std::size_t>(wideSize));
        if (MultiByteToWideChar(CP_UTF8, 0, utf8Text.c_str(), static_cast<int>(utf8Text.size()), buffer.data(), wideSize) <= 0)
        {
            return false;
        }
        wideTextOut.assign(buffer.data(), static_cast<std::size_t>(wideSize));
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// Windows (not cmd.exe) command-line argument quoting -- the standard reverse algorithm for how
// CommandLineToArgvW/the MSVC CRT parse a command line back into argv, applied here to BUILD one.
// Since CreateProcessW is invoked directly (no cmd.exe in between), this is the only quoting rule
// that matters -- cmd.exe's own separate quote-stripping quirk (relevant to the repo's existing
// _popen-based test helpers) does not apply. Operating on raw UTF-8 bytes here is safe: quoting
// only ever inspects the ASCII characters space/tab/quote/backslash, none of which can appear as a
// continuation byte of a multi-byte UTF-8 sequence (those are always >= 0x80).
// ================================================================================================

std::string quoteWindowsArgument(const std::string& arg)
{
    if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == std::string::npos)
    {
        return arg;
    }
    std::string result = "\"";
    for (std::size_t i = 0; ; )
    {
        std::size_t backslashCount = 0;
        while (i < arg.size() && arg[i] == '\\')
        {
            ++backslashCount;
            ++i;
        }
        if (i == arg.size())
        {
            result.append(backslashCount * 2, '\\');
            break;
        }
        else if (arg[i] == '"')
        {
            result.append(backslashCount * 2 + 1, '\\');
            result.push_back('"');
            ++i;
        }
        else
        {
            result.append(backslashCount, '\\');
            result.push_back(arg[i]);
            ++i;
        }
    }
    result.push_back('"');
    return result;
}
// -----------------------------------------------------------------------------

std::string buildCommandLine(const std::vector<std::string>& argv)
{
    std::string line;
    for (std::size_t i = 0; i < argv.size(); ++i)
    {
        if (i > 0)
        {
            line.push_back(' ');
        }
        line += quoteWindowsArgument(argv[i]);
    }
    return line;
}
// -----------------------------------------------------------------------------

// ================================================================================================
// Subprocess execution -- CreateProcessW with fully redirected, non-inheritable-on-the-parent-side
// stdio pipes (stdout and stderr share one pipe, so callers see gpg's combined output the same way
// a "2>&1" shell redirection would). No cmd.exe involved anywhere. stdinData (if non-empty) is
// written and the write end closed (signals EOF) before the combined output pipe is drained, which
// is safe from deadlock here because every caller in this file either supplies a small, bounded
// stdinData (a passphrase/short script) or none at all, and never expects gpg to write a large
// payload to stdout itself (bulk data always flows through --output <file>, not stdout).
// ================================================================================================

struct GpgProcessResult
{
    bool started;
    DWORD exitCode;
    std::string output;

    GpgProcessResult() : started(false), exitCode(static_cast<DWORD>(-1)) {}
};
// -----------------------------------------------------------------------------

GpgProcessResult runGpgProcess(const std::vector<std::string>& argv, const std::string& stdinData)
{
    GpgProcessResult result;
    HANDLE stdinReadHandle = nullptr;
    HANDLE stdinWriteHandle = nullptr;
    HANDLE stdoutReadHandle = nullptr;
    HANDLE stdoutWriteHandle = nullptr;
    PROCESS_INFORMATION processInfo;
    ZeroMemory(&processInfo, sizeof(processInfo));

    try
    {
        SECURITY_ATTRIBUTES securityAttributes;
        ZeroMemory(&securityAttributes, sizeof(securityAttributes));
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.bInheritHandle = TRUE;
        securityAttributes.lpSecurityDescriptor = nullptr;

        if (!CreatePipe(&stdinReadHandle, &stdinWriteHandle, &securityAttributes, 0))
        {
            return result;
        }
        if (!SetHandleInformation(stdinWriteHandle, HANDLE_FLAG_INHERIT, 0))
        {
            CloseHandle(stdinReadHandle);
            CloseHandle(stdinWriteHandle);
            return result;
        }

        if (!CreatePipe(&stdoutReadHandle, &stdoutWriteHandle, &securityAttributes, 0))
        {
            CloseHandle(stdinReadHandle);
            CloseHandle(stdinWriteHandle);
            return result;
        }
        if (!SetHandleInformation(stdoutReadHandle, HANDLE_FLAG_INHERIT, 0))
        {
            CloseHandle(stdinReadHandle);
            CloseHandle(stdinWriteHandle);
            CloseHandle(stdoutReadHandle);
            CloseHandle(stdoutWriteHandle);
            return result;
        }

        STARTUPINFOW startupInfo;
        ZeroMemory(&startupInfo, sizeof(startupInfo));
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESTDHANDLES;
        startupInfo.hStdInput = stdinReadHandle;
        startupInfo.hStdOutput = stdoutWriteHandle;
        startupInfo.hStdError = stdoutWriteHandle;

        const std::string commandLineUtf8 = buildCommandLine(argv);
        std::wstring commandLineWide;
        if (!utf8ToWide(commandLineUtf8, commandLineWide))
        {
            CloseHandle(stdinReadHandle);
            CloseHandle(stdinWriteHandle);
            CloseHandle(stdoutReadHandle);
            CloseHandle(stdoutWriteHandle);
            return result;
        }
        std::vector<wchar_t> mutableCommandLine(commandLineWide.begin(), commandLineWide.end());
        mutableCommandLine.push_back(L'\0');

        const BOOL created = CreateProcessW( nullptr, mutableCommandLine.data(), nullptr, nullptr, TRUE,
                                            CREATE_NO_WINDOW, nullptr, nullptr, &startupInfo, &processInfo);

        CloseHandle(stdinReadHandle);
        stdinReadHandle = nullptr;
        CloseHandle(stdoutWriteHandle);
        stdoutWriteHandle = nullptr;

        if (!created)
        {
            CloseHandle(stdinWriteHandle);
            CloseHandle(stdoutReadHandle);
            return result;
        }

        result.started = true;

        if (!stdinData.empty())
        {
            DWORD bytesWritten = 0;
            WriteFile(stdinWriteHandle, stdinData.data(), static_cast<DWORD>(stdinData.size()), &bytesWritten, nullptr);
        }
        CloseHandle(stdinWriteHandle);
        stdinWriteHandle = nullptr;

        char readBuffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(stdoutReadHandle, readBuffer, sizeof(readBuffer), &bytesRead, nullptr) && bytesRead > 0)
        {
            result.output.append(readBuffer, bytesRead);
        }
        CloseHandle(stdoutReadHandle);
        stdoutReadHandle = nullptr;

        WaitForSingleObject(processInfo.hProcess, INFINITE);
        GetExitCodeProcess(processInfo.hProcess, &result.exitCode);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);

        return result;
    }
    catch (...)
    {
        if (stdinReadHandle != nullptr) { CloseHandle(stdinReadHandle); }
        if (stdinWriteHandle != nullptr) { CloseHandle(stdinWriteHandle); }
        if (stdoutReadHandle != nullptr) { CloseHandle(stdoutReadHandle); }
        if (stdoutWriteHandle != nullptr) { CloseHandle(stdoutWriteHandle); }
        if (processInfo.hProcess != nullptr) { CloseHandle(processInfo.hProcess); }
        if (processInfo.hThread != nullptr) { CloseHandle(processInfo.hThread); }
        result.started = false;
        return result;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// Plain temp-file I/O for the Buffer-suffixed methods' round trip through gpg. Paths passed here
// are always ones this class generated itself (ASCII-only, under its own homedir), never arbitrary
// caller-supplied Unicode paths, so plain narrow-char std::ofstream/ifstream is sufficient --
// caller-supplied paths (the File-suffixed methods) are instead passed straight through to gpg as
// UTF-8 command-line arguments, never opened directly by this class.
// ================================================================================================

bool writeAllBytesToFile(const std::string& path, const unsigned char* data, const std::size_t size)
{
    try
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.good())
        {
            return false;
        }
        if (size > 0)
        {
            file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
        }
        return file.good();
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool readAllBytesFromFile(const std::string& path, std::vector<unsigned char>& out)
{
    try
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.good())
        {
            return false;
        }
        const std::streamoff size = file.tellg();
        if (size < 0)
        {
            return false;
        }
        out.resize(static_cast<std::size_t>(size));
        if (size > 0)
        {
            file.seekg(0);
            file.read(reinterpret_cast<char*>(out.data()), size);
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool fileExistsUtf8(const std::string& utf8Path)
{
    try
    {
        std::wstring widePath;
        if (!utf8ToWide(utf8Path, widePath))
        {
            return false;
        }
        const DWORD attributes = GetFileAttributesW(widePath.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// "gpg --batch --gen-key" parameter-file plumbing, colon-format ("--with-colons") output parsing,
// and the revocation-reason menu-index translation this class documents in its header.
// ================================================================================================

void parseUserIdNameEmail(const std::string& userId, std::string& nameOut, std::string& emailOut)
{
    const std::size_t lt = userId.find('<');
    const std::size_t gt = (lt == std::string::npos) ? std::string::npos : userId.find('>', lt);
    if (lt != std::string::npos && gt != std::string::npos && gt > lt)
    {
        std::string name = userId.substr(0, lt);
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
        {
            name.erase(name.size() - 1);
        }
        nameOut = name.empty() ? std::string("PGP User") : name;
        emailOut = userId.substr(lt + 1, gt - lt - 1);
    }
    else
    {
        nameOut = userId.empty() ? std::string("PGP User") : userId;
        emailOut = "pgpwrapper@example.invalid";
    }
    if (emailOut.empty())
    {
        emailOut = "pgpwrapper@example.invalid";
    }
}
// -----------------------------------------------------------------------------

std::string keyIdFromFingerprint(const std::string& fingerprint)
{
    if (fingerprint.size() < 16)
    {
        return std::string();
    }
    std::string result = fingerprint.substr(fingerprint.size() - 16);
    for (std::size_t i = 0; i < result.size(); ++i)
    {
        result[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(result[i])));
    }
    return result;
}
// -----------------------------------------------------------------------------

// The colon-format "fpr" record (RFC-less, gpg's own --with-colons convention) is
// "fpr:::::::::<fingerprint>:" -- field 10 (1-indexed), i.e. index 9 when split on ':'.
bool findFirstFingerprintInColonOutput(const std::string& colonOutput, std::string& fingerprintOut)
{
    try
    {
        std::istringstream lineStream(colonOutput);
        std::string line;
        while (std::getline(lineStream, line))
        {
            if (line.rfind("fpr:", 0) == 0)
            {
                std::vector<std::string> fields;
                std::istringstream fieldStream(line);
                std::string field;
                while (std::getline(fieldStream, field, ':'))
                {
                    fields.push_back(field);
                }
                if (fields.size() > 9 && !fields[9].empty())
                {
                    fingerprintOut = fields[9];
                    return true;
                }
            }
        }
        return false;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// "gpg --status-fd" emits a machine-readable "[GNUPG:] IMPORTED <keyid> <userid...>" line per
// newly-considered primary key on --import; this class treats the first such line as identifying
// the peer key ImportPeerPublicKey was asked to import.
bool findFirstImportedKeyId(const std::string& statusOutput, std::string& keyIdOut)
{
    try
    {
        const std::string marker = "[GNUPG:] IMPORTED ";
        std::istringstream lineStream(statusOutput);
        std::string line;
        while (std::getline(lineStream, line))
        {
            const std::size_t markerPos = line.find(marker);
            if (markerPos != std::string::npos)
            {
                const std::size_t start = markerPos + marker.size();
                std::size_t end = line.find(' ', start);
                if (end == std::string::npos)
                {
                    end = line.size();
                }
                std::string id = line.substr(start, end - start);
                for (std::size_t i = 0; i < id.size(); ++i)
                {
                    id[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(id[i])));
                }
                if (id.size() >= 16)
                {
                    keyIdOut = id.substr(id.size() - 16);
                    return true;
                }
            }
        }
        return false;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Translates CPgpEngineWrapper's own RevokeKeyArmored reasonCode (RFC 4880 5.2.3.23 numbering,
// same as CPgpEngine's own RevokeKeyArmored: 0=no reason,1=superseded,2=compromised,3=retired)
// into the numeric answer gpg's own "--generate-revocation" interactive menu expects at its
// "ask_revocation_reason.code" prompt. Verified empirically against this machine's installed
// gpg.exe (2.5.21) while building this class: selecting menu option "1" produces an RFC subpacket
// byte of 0x02 (compromised) and menu option "2" produces 0x01 (superseded) -- i.e. gpg's own menu
// order does NOT match RFC 4880's numeric assignment 1:1, so a direct pass-through would silently
// swap "superseded" and "compromised" for every wrapper caller.
int mapRevocationReasonToGpgMenu(const unsigned char rfcReasonCode)
{
    switch (rfcReasonCode)
    {
        case 0: return 0;
        case 1: return 2;
        case 2: return 1;
        case 3: return 3;
        default: return 0;
    }
}
// -----------------------------------------------------------------------------

std::string sanitizeSingleLine(const std::string& text)
{
    std::string result = text;
    for (std::size_t i = 0; i < result.size(); ++i)
    {
        if (result[i] == '\n' || result[i] == '\r')
        {
            result[i] = ' ';
        }
    }
    return result;
}
// -----------------------------------------------------------------------------

} // anonymous namespace

// ================================================================================================
// Impl -- kept out of the header so callers never need Windows.h/gpg's own concepts. Holds this
// instance's isolated --homedir, discovered gpg.exe path, current-identity/peer-keyring state, and
// every private helper that shells out to gpg on behalf of a public CPgpEngineWrapper method.
// ================================================================================================

struct CPgpEngineWrapper::Impl
{
    bool gpgFound;
    std::string gpgExePath;
    bool homeDirReady;
    std::string homeDir;
    int rsaKeyBits;
    int tempFileCounter;

    bool ownKeyGenerated;
    std::string ownKeyId;
    std::string ownPublicKeyArmored;
    std::string ownSecretKeyArmored;
    unsigned int keyExpirationSeconds;

    std::vector<std::string> peerKeyIds;

    Impl();
    ~Impl();

    std::string makeTempPath(const char* suffix);
    std::vector<std::string> baseArgs(void) const;

    int generateKeyPairInternal( const char* userId, const int userIdSize,
                                const char* password, const int passwordSize,
                                const unsigned int expirationSeconds, const bool isEcc);

    int encryptCommon( const unsigned char* inputBuffer, const int inputBufferSize,
                      const std::vector<std::string>& recipientIds, const bool armor,
                      std::vector<unsigned char>& outBytes);

    int decryptCommon( const char* password, const int passwordSize,
                      const unsigned char* inputBuffer, const int inputBufferSize,
                      const char* tempSuffix, std::vector<unsigned char>& outPlain);

    int signCommon( const char* password, const int passwordSize,
                   const unsigned char* inputBuffer, const int inputBufferSize,
                   std::vector<unsigned char>& outSignature);

    int verifyDetachedCommon( const unsigned char* inputBuffer, const int inputBufferSize,
                             const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid);

    int clearSignCommon( const char* password, const int passwordSize,
                        const char* inputString, const int inputStringSize,
                        std::string& outArmored);

    int verifyClearSignedCommon(const char* clearSignedString, const int clearSignedStringSize, bool* isValid);

    int importPeerPublicKeyCommon(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize, std::string& newKeyIdOut);

    int revokeKeyCommon( const char* password, const int passwordSize,
                        const unsigned char reasonCode, const char* reasonText, const int reasonTextSize,
                        std::string& outArmored);
};
// -----------------------------------------------------------------------------

CPgpEngineWrapper::Impl::Impl() : gpgFound(false), homeDirReady(false), rsaKeyBits(2048), tempFileCounter(0),
                                   ownKeyGenerated(false), keyExpirationSeconds(0)
{
    try
    {
        gpgExePath = findGpgExecutableForWrapper();
        gpgFound = !gpgExePath.empty();

        char tempPathBuffer[MAX_PATH];
        const DWORD tempPathLen = GetTempPathA(MAX_PATH, tempPathBuffer);
        std::string base = (tempPathLen > 0 && tempPathLen < MAX_PATH) ? std::string(tempPathBuffer, tempPathLen) : std::string("C:\\Windows\\Temp\\");
        if (!base.empty() && base[base.size() - 1] != '\\')
        {
            base.push_back('\\');
        }

        std::ostringstream nameStream;
        nameStream << "pgpw_" << GetCurrentProcessId() << "_" << GetTickCount64() << "_" << (reinterpret_cast<std::uintptr_t>(this) & 0xFFFFu);
        homeDir = base + nameStream.str();

        std::error_code creationError;
        homeDirReady = std::filesystem::create_directories(homeDir, creationError) || std::filesystem::exists(homeDir);
    }
    catch (...)
    {
        gpgFound = false;
        homeDirReady = false;
    }
}
// -----------------------------------------------------------------------------

CPgpEngineWrapper::Impl::~Impl()
{
    try
    {
        if (!homeDir.empty())
        {
            std::error_code removalError;
            std::filesystem::remove_all(homeDir, removalError);
        }
    }
    catch (...)
    {
    }
}
// -----------------------------------------------------------------------------

std::string CPgpEngineWrapper::Impl::makeTempPath(const char* suffix)
{
    ++tempFileCounter;
    std::ostringstream pathStream;
    pathStream << homeDir << "\\t" << tempFileCounter << suffix;
    return pathStream.str();
}
// -----------------------------------------------------------------------------

std::vector<std::string> CPgpEngineWrapper::Impl::baseArgs(void) const
{
    std::vector<std::string> args;
    args.push_back(gpgExePath);
    args.push_back("--homedir");
    args.push_back(homeDir);
    args.push_back("--batch");
    args.push_back("--yes");
    return args;
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::Impl::generateKeyPairInternal( const char* userId, const int userIdSize,
                                                      const char* password, const int passwordSize,
                                                      const unsigned int expirationSeconds, const bool isEcc)
{
    try
    {
        if (userId == nullptr || userIdSize <= 0 || password == nullptr || passwordSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (!isEcc && rsaKeyBits != 1024 && rsaKeyBits != 2048 && rsaKeyBits != 3072 && rsaKeyBits != 4096)
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        std::string name;
        std::string email;
        parseUserIdNameEmail(std::string(userId, static_cast<std::size_t>(userIdSize)), name, email);
        const std::string passwordStr(password, static_cast<std::size_t>(passwordSize));
        const std::string expireSpec = (expirationSeconds == 0) ? std::string("0") : (std::string("seconds=") + std::to_string(expirationSeconds));

        std::ostringstream batch;
        batch << "%echo generating key\n";
        if (isEcc)
        {
            batch << "Key-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign,cert\n";
            batch << "Subkey-Type: ecdh\nSubkey-Curve: cv25519\nSubkey-Usage: encrypt\n";
        }
        else
        {
            batch << "Key-Type: RSA\nKey-Length: " << rsaKeyBits << "\nKey-Usage: sign,cert\n";
            batch << "Subkey-Type: RSA\nSubkey-Length: " << rsaKeyBits << "\nSubkey-Usage: encrypt\n";
        }
        batch << "Name-Real: " << name << "\n";
        batch << "Name-Email: " << email << "\n";
        batch << "Expire-Date: " << expireSpec << "\n";
        batch << "Passphrase: " << passwordStr << "\n";
        batch << "%commit\n";

        std::vector<std::string> genArgs = baseArgs();
        genArgs.push_back("--gen-key");
        const GpgProcessResult genResult = runGpgProcess(genArgs, batch.str());
        if (!genResult.started || genResult.exitCode != 0)
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<std::string> listArgs = baseArgs();
        listArgs.push_back("--with-colons");
        listArgs.push_back("--fingerprint");
        listArgs.push_back("--list-secret-keys");
        listArgs.push_back(email);
        const GpgProcessResult listResult = runGpgProcess(listArgs, std::string());
        std::string fingerprint;
        if (!listResult.started || !findFirstFingerprintInColonOutput(listResult.output, fingerprint))
        {
            return UNEXPECTED_ERROR;
        }
        const std::string keyId = keyIdFromFingerprint(fingerprint);
        if (keyId.size() != 16)
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<std::string> exportPubArgs = baseArgs();
        exportPubArgs.push_back("--armor");
        exportPubArgs.push_back("--export");
        exportPubArgs.push_back(keyId);
        const GpgProcessResult exportPubResult = runGpgProcess(exportPubArgs, std::string());
        if (!exportPubResult.started || exportPubResult.exitCode != 0 ||
            exportPubResult.output.find("-----BEGIN PGP PUBLIC KEY BLOCK-----") == std::string::npos)
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<std::string> exportSecArgs = baseArgs();
        exportSecArgs.push_back("--pinentry-mode");
        exportSecArgs.push_back("loopback");
        exportSecArgs.push_back("--passphrase-fd");
        exportSecArgs.push_back("0");
        exportSecArgs.push_back("--armor");
        exportSecArgs.push_back("--export-secret-keys");
        exportSecArgs.push_back(keyId);
        std::string exportSecStdin = passwordStr;
        exportSecStdin.push_back('\n');
        const GpgProcessResult exportSecResult = runGpgProcess(exportSecArgs, exportSecStdin);
        if (!exportSecResult.started || exportSecResult.exitCode != 0 ||
            exportSecResult.output.find("-----BEGIN PGP PRIVATE KEY BLOCK-----") == std::string::npos)
        {
            return UNEXPECTED_ERROR;
        }

        ownKeyGenerated = true;
        ownKeyId = keyId;
        ownPublicKeyArmored = exportPubResult.output;
        ownSecretKeyArmored = exportSecResult.output;
        keyExpirationSeconds = expirationSeconds;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::Impl::encryptCommon( const unsigned char* inputBuffer, const int inputBufferSize,
                                           const std::vector<std::string>& recipientIds, const bool armor,
                                           std::vector<unsigned char>& outBytes)
{
    try
    {
        if (recipientIds.empty())
        {
            return INVALID_ARGUMENT;
        }
        if (inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        const std::string inPath = makeTempPath(".in");
        const std::string outPath = makeTempPath(armor ? ".asc" : ".gpg");
        if (!writeAllBytesToFile(inPath, inputBuffer, static_cast<std::size_t>(inputBufferSize)))
        {
            return FILE_IO_ERROR;
        }

        std::vector<std::string> args = baseArgs();
        args.push_back("--trust-model");
        args.push_back("always");
        for (std::size_t i = 0; i < recipientIds.size(); ++i)
        {
            args.push_back("-r");
            args.push_back(recipientIds[i]);
        }
        if (armor)
        {
            args.push_back("--armor");
        }
        args.push_back("--output");
        args.push_back(outPath);
        args.push_back("--encrypt");
        args.push_back(inPath);

        const GpgProcessResult result = runGpgProcess(args, std::string());
        std::remove(inPath.c_str());
        if (!result.started || result.exitCode != 0)
        {
            std::remove(outPath.c_str());
            return UNEXPECTED_ERROR;
        }

        const bool readOk = readAllBytesFromFile(outPath, outBytes);
        std::remove(outPath.c_str());
        if (!readOk)
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

int CPgpEngineWrapper::Impl::decryptCommon( const char* password, const int passwordSize,
                                           const unsigned char* inputBuffer, const int inputBufferSize,
                                           const char* tempSuffix, std::vector<unsigned char>& outPlain)
{
    try
    {
        if (!ownKeyGenerated)
        {
            return INVALID_ARGUMENT;
        }
        if (password == nullptr || passwordSize <= 0 || inputBuffer == nullptr || inputBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        const std::string inPath = makeTempPath(tempSuffix);
        const std::string outPath = makeTempPath(".out");
        if (!writeAllBytesToFile(inPath, inputBuffer, static_cast<std::size_t>(inputBufferSize)))
        {
            return FILE_IO_ERROR;
        }

        std::vector<std::string> args = baseArgs();
        args.push_back("--pinentry-mode");
        args.push_back("loopback");
        args.push_back("--passphrase-fd");
        args.push_back("0");
        args.push_back("--output");
        args.push_back(outPath);
        args.push_back("--decrypt");
        args.push_back(inPath);

        std::string stdinData(password, static_cast<std::size_t>(passwordSize));
        stdinData.push_back('\n');

        const GpgProcessResult result = runGpgProcess(args, stdinData);
        std::remove(inPath.c_str());
        if (!result.started || result.exitCode != 0)
        {
            std::remove(outPath.c_str());
            return INVALID_DATA;
        }

        const bool readOk = readAllBytesFromFile(outPath, outPlain);
        std::remove(outPath.c_str());
        if (!readOk)
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

int CPgpEngineWrapper::Impl::signCommon( const char* password, const int passwordSize,
                                        const unsigned char* inputBuffer, const int inputBufferSize,
                                        std::vector<unsigned char>& outSignature)
{
    try
    {
        if (!ownKeyGenerated)
        {
            return INVALID_ARGUMENT;
        }
        if (password == nullptr || passwordSize <= 0 || inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        const std::string inPath = makeTempPath(".in");
        const std::string sigPath = makeTempPath(".sig");
        if (!writeAllBytesToFile(inPath, inputBuffer, static_cast<std::size_t>(inputBufferSize)))
        {
            return FILE_IO_ERROR;
        }

        std::vector<std::string> args = baseArgs();
        args.push_back("--pinentry-mode");
        args.push_back("loopback");
        args.push_back("--passphrase-fd");
        args.push_back("0");
        args.push_back("--local-user");
        args.push_back(ownKeyId);
        args.push_back("--output");
        args.push_back(sigPath);
        args.push_back("--detach-sign");
        args.push_back(inPath);

        std::string stdinData(password, static_cast<std::size_t>(passwordSize));
        stdinData.push_back('\n');

        const GpgProcessResult result = runGpgProcess(args, stdinData);
        std::remove(inPath.c_str());
        if (!result.started || result.exitCode != 0)
        {
            std::remove(sigPath.c_str());
            return UNEXPECTED_ERROR;
        }

        const bool readOk = readAllBytesFromFile(sigPath, outSignature);
        std::remove(sigPath.c_str());
        if (!readOk)
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

int CPgpEngineWrapper::Impl::verifyDetachedCommon( const unsigned char* inputBuffer, const int inputBufferSize,
                                                  const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid)
{
    try
    {
        if (peerKeyIds.empty() || isValid == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr) ||
            signatureBuffer == nullptr || signatureBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        const std::string docPath = makeTempPath(".doc");
        const std::string sigPath = makeTempPath(".sig");
        if (!writeAllBytesToFile(docPath, inputBuffer, static_cast<std::size_t>(inputBufferSize)) ||
            !writeAllBytesToFile(sigPath, signatureBuffer, static_cast<std::size_t>(signatureBufferSize)))
        {
            std::remove(docPath.c_str());
            std::remove(sigPath.c_str());
            return FILE_IO_ERROR;
        }

        std::vector<std::string> args = baseArgs();
        args.push_back("--verify");
        args.push_back(sigPath);
        args.push_back(docPath);

        const GpgProcessResult result = runGpgProcess(args, std::string());
        std::remove(docPath.c_str());
        std::remove(sigPath.c_str());
        if (!result.started)
        {
            return UNEXPECTED_ERROR;
        }

        *isValid = (result.exitCode == 0);
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::Impl::clearSignCommon( const char* password, const int passwordSize,
                                             const char* inputString, const int inputStringSize,
                                             std::string& outArmored)
{
    try
    {
        if (!ownKeyGenerated)
        {
            return INVALID_ARGUMENT;
        }
        if (password == nullptr || passwordSize <= 0 || inputString == nullptr || inputStringSize < 0)
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        const std::string inPath = makeTempPath(".txt");
        const std::string outPath = makeTempPath(".asc");
        if (!writeAllBytesToFile(inPath, reinterpret_cast<const unsigned char*>(inputString), static_cast<std::size_t>(inputStringSize)))
        {
            return FILE_IO_ERROR;
        }

        std::vector<std::string> args = baseArgs();
        args.push_back("--pinentry-mode");
        args.push_back("loopback");
        args.push_back("--passphrase-fd");
        args.push_back("0");
        args.push_back("--local-user");
        args.push_back(ownKeyId);
        args.push_back("--output");
        args.push_back(outPath);
        args.push_back("--clear-sign");
        args.push_back(inPath);

        std::string stdinData(password, static_cast<std::size_t>(passwordSize));
        stdinData.push_back('\n');

        const GpgProcessResult result = runGpgProcess(args, stdinData);
        std::remove(inPath.c_str());
        if (!result.started || result.exitCode != 0)
        {
            std::remove(outPath.c_str());
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> outBytes;
        const bool readOk = readAllBytesFromFile(outPath, outBytes);
        std::remove(outPath.c_str());
        if (!readOk)
        {
            return FILE_IO_ERROR;
        }
        outArmored.assign(outBytes.begin(), outBytes.end());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::Impl::verifyClearSignedCommon(const char* clearSignedString, const int clearSignedStringSize, bool* isValid)
{
    try
    {
        if (peerKeyIds.empty() || isValid == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (clearSignedString == nullptr || clearSignedStringSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        const std::string path = makeTempPath(".asc");
        if (!writeAllBytesToFile(path, reinterpret_cast<const unsigned char*>(clearSignedString), static_cast<std::size_t>(clearSignedStringSize)))
        {
            return FILE_IO_ERROR;
        }

        std::vector<std::string> args = baseArgs();
        args.push_back("--verify");
        args.push_back(path);

        const GpgProcessResult result = runGpgProcess(args, std::string());
        std::remove(path.c_str());
        if (!result.started)
        {
            return UNEXPECTED_ERROR;
        }

        *isValid = (result.exitCode == 0);
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::Impl::importPeerPublicKeyCommon(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize, std::string& newKeyIdOut)
{
    try
    {
        if (keyBlockBuffer == nullptr || keyBlockBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        const std::string path = makeTempPath(".key");
        if (!writeAllBytesToFile(path, keyBlockBuffer, static_cast<std::size_t>(keyBlockBufferSize)))
        {
            return FILE_IO_ERROR;
        }

        std::vector<std::string> args = baseArgs();
        args.push_back("--status-fd");
        args.push_back("1");
        args.push_back("--import");
        args.push_back(path);

        const GpgProcessResult result = runGpgProcess(args, std::string());
        std::remove(path.c_str());
        if (!result.started)
        {
            return UNEXPECTED_ERROR;
        }

        std::string keyId;
        if (findFirstImportedKeyId(result.output, keyId))
        {
            // gpg has been observed (see this class's header comment and RevokeKeyArmored below)
            // to occasionally report success via its own status/output channel while still
            // exiting non-zero on unrelated trustdb bookkeeping -- an IMPORTED status line is
            // treated as the real verdict here regardless of exit code, same philosophy as
            // RevokeKeyArmored using "did the output file get written" as its own verdict.
            newKeyIdOut = keyId;
            return NO_ERROR;
        }
        if (result.exitCode != 0)
        {
            return UNEXPECTED_ERROR;
        }
        return INVALID_DATA;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::Impl::revokeKeyCommon( const char* password, const int passwordSize,
                                             const unsigned char reasonCode, const char* reasonText, const int reasonTextSize,
                                             std::string& outArmored)
{
    try
    {
        if (!ownKeyGenerated)
        {
            return INVALID_ARGUMENT;
        }
        if (password == nullptr || passwordSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (!gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }

        const std::string outPath = makeTempPath(".rev");
        const int gpgMenuChoice = mapRevocationReasonToGpgMenu(reasonCode);
        std::string reasonTextStr = (reasonText != nullptr && reasonTextSize > 0) ? std::string(reasonText, static_cast<std::size_t>(reasonTextSize)) : std::string();
        reasonTextStr = sanitizeSingleLine(reasonTextStr);

        // gpg's "ask_revocation_reason.text" prompt is a multi-line entry terminated by one blank
        // line: when reasonTextStr is non-empty it occupies its own line before that blank
        // terminator, but when it is empty the SAME blank line serves as both the (empty) reason
        // text and its own terminator -- feeding an extra blank line in that case (verified
        // empirically against this machine's gpg.exe while building this class) desynchronizes
        // every prompt after it, including the passphrase read, and the whole script fails.
        std::ostringstream stdinScript;
        stdinScript << "y\n" << gpgMenuChoice << "\n";
        if (!reasonTextStr.empty())
        {
            stdinScript << reasonTextStr << "\n";
        }
        stdinScript << "\ny\n" << std::string(password, static_cast<std::size_t>(passwordSize)) << "\n";

        // NOT baseArgs() here: "--generate-revocation" drives an interactive command-fd/pinentry
        // script (see the stdinScript built above), and gpg rejects that combination outright
        // with "can't do this in batch mode" when --batch is also present (verified empirically
        // against this machine's gpg.exe while building this class) -- every other method in this
        // file uses --batch because it never needs an interactive prompt sequence, but this one
        // must omit it.
        std::vector<std::string> args;
        args.push_back(gpgExePath);
        args.push_back("--homedir");
        args.push_back(homeDir);
        args.push_back("--yes");
        args.push_back("--pinentry-mode");
        args.push_back("loopback");
        args.push_back("--command-fd");
        args.push_back("0");
        args.push_back("--output");
        args.push_back(outPath);
        args.push_back("--generate-revocation");
        args.push_back(ownKeyId);

        const GpgProcessResult result = runGpgProcess(args, stdinScript.str());
        if (!result.started)
        {
            return UNEXPECTED_ERROR;
        }

        // Same quirk-tolerance philosophy as ImportPeerPublicKey above: the real verdict is
        // whether gpg actually produced a non-empty revocation certificate file, not its exit
        // code (observed, while building this class, to sometimes be non-zero on unrelated
        // trustdb bookkeeping even after a successful --generate-revocation).
        std::vector<unsigned char> outBytes;
        const bool readOk = readAllBytesFromFile(outPath, outBytes);
        std::remove(outPath.c_str());
        if (!readOk || outBytes.empty())
        {
            return UNEXPECTED_ERROR;
        }
        outArmored.assign(outBytes.begin(), outBytes.end());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

CPgpEngineWrapper::~CPgpEngineWrapper()
{
}
// -----------------------------------------------------------------------------

CPgpEngineWrapper::CPgpEngineWrapper()
{
    try
    {
        impl_.reset(new Impl());
    }
    catch (...)
    {
        impl_.reset();
    }
}
// -----------------------------------------------------------------------------

CPgpEngineWrapper::CPgpEngineWrapper(const int rsaKeyBits)
{
    try
    {
        impl_.reset(new Impl());
        if (impl_)
        {
            impl_->rsaKeyBits = rsaKeyBits;
        }
    }
    catch (...)
    {
        impl_.reset();
    }
}
// -----------------------------------------------------------------------------

bool CPgpEngineWrapper::IsGnuPgAvailable(void) const
{
    try
    {
        return impl_ && impl_->gpgFound;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GenerateKeyPair(const char* userId, const int userIdSize, const char* password, const int passwordSize)
{
    return GenerateKeyPair(userId, userIdSize, password, passwordSize, 0);
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GenerateKeyPair(const char* userId, const int userIdSize, const char* password, const int passwordSize, const unsigned int expirationSeconds)
{
    try
    {
        if (!impl_)
        {
            return INVALID_ARGUMENT;
        }
        return impl_->generateKeyPairInternal(userId, userIdSize, password, passwordSize, expirationSeconds, false);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GenerateKeyPairEcc(const char* userId, const int userIdSize, const char* password, const int passwordSize)
{
    return GenerateKeyPairEcc(userId, userIdSize, password, passwordSize, 0);
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GenerateKeyPairEcc(const char* userId, const int userIdSize, const char* password, const int passwordSize, const unsigned int expirationSeconds)
{
    try
    {
        if (!impl_)
        {
            return INVALID_ARGUMENT;
        }
        return impl_->generateKeyPairInternal(userId, userIdSize, password, passwordSize, expirationSeconds, true);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

unsigned int CPgpEngineWrapper::GetKeyExpirationSeconds(void) const
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated)
        {
            return 0;
        }
        return impl_->keyExpirationSeconds;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GetPublicKeyArmoredSize(void) const
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated)
        {
            return 0;
        }
        return static_cast<int>(impl_->ownPublicKeyArmored.size());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GetSecretKeyArmoredSize(void) const
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated)
        {
            return 0;
        }
        return static_cast<int>(impl_->ownSecretKeyArmored.size());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::ExportPublicKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        const std::string& armored = impl_->ownPublicKeyArmored;
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armored.size()))
        {
            *outputBufferSize = static_cast<int>(armored.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, armored.data(), armored.size());
        *outputBufferSize = static_cast<int>(armored.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::ExportSecretKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        const std::string& armored = impl_->ownSecretKeyArmored;
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armored.size()))
        {
            *outputBufferSize = static_cast<int>(armored.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, armored.data(), armored.size());
        *outputBufferSize = static_cast<int>(armored.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GetKeyId(char* outputBuffer, const int outputBufferCapacity) const
{
    try
    {
        if (!impl_ || outputBuffer == nullptr || outputBufferCapacity < 17)
        {
            return BUFFER_TOO_SMALL;
        }
        if (!impl_->ownKeyGenerated)
        {
            outputBuffer[0] = '\0';
            return NO_ERROR;
        }
        std::memcpy(outputBuffer, impl_->ownKeyId.data(), 16);
        outputBuffer[16] = '\0';
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::RevokeKeyArmored( const char* password, const int passwordSize,
                                        const unsigned char reasonCode, const char* reasonText, const int reasonTextSize,
                                        const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        std::string armored;
        const int status = impl_->revokeKeyCommon(password, passwordSize, reasonCode, reasonText, reasonTextSize, armored);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armored.size()))
        {
            *outputBufferSize = static_cast<int>(armored.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, armored.data(), armored.size());
        *outputBufferSize = static_cast<int>(armored.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::ImportPeerPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize)
{
    try
    {
        if (!impl_)
        {
            return INVALID_ARGUMENT;
        }
        std::string newKeyId;
        const int status = impl_->importPeerPublicKeyCommon(keyBlockBuffer, keyBlockBufferSize, newKeyId);
        if (status != NO_ERROR)
        {
            return status;
        }
        impl_->peerKeyIds.push_back(newKeyId);
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GetPeerKeyId(char* outputBuffer, const int outputBufferCapacity) const
{
    try
    {
        if (!impl_ || outputBuffer == nullptr || outputBufferCapacity < 17)
        {
            return BUFFER_TOO_SMALL;
        }
        if (impl_->peerKeyIds.empty())
        {
            outputBuffer[0] = '\0';
            return NO_ERROR;
        }
        const std::string& lastId = impl_->peerKeyIds.back();
        std::memcpy(outputBuffer, lastId.data(), 16);
        outputBuffer[16] = '\0';
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GetImportedPeerKeyCount(void) const
{
    try
    {
        if (!impl_)
        {
            return 0;
        }
        return static_cast<int>(impl_->peerKeyIds.size());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::GetImportedPeerKeyId(const int peerIndex, char* outputBuffer, const int outputBufferCapacity) const
{
    try
    {
        if (!impl_ || peerIndex < 0 || peerIndex >= static_cast<int>(impl_->peerKeyIds.size()))
        {
            return INVALID_ARGUMENT;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < 17)
        {
            return BUFFER_TOO_SMALL;
        }
        const std::string& id = impl_->peerKeyIds[static_cast<std::size_t>(peerIndex)];
        std::memcpy(outputBuffer, id.data(), 16);
        outputBuffer[16] = '\0';
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::EncryptBuffer(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (impl_->peerKeyIds.empty())
        {
            return INVALID_ARGUMENT;
        }
        std::vector<std::string> recipients(1, impl_->peerKeyIds.back());
        std::vector<unsigned char> cipherBytes;
        const int status = impl_->encryptCommon(inputBuffer, inputBufferSize, recipients, false, cipherBytes);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(cipherBytes.size()))
        {
            *outputBufferSize = static_cast<int>(cipherBytes.size());
            return BUFFER_TOO_SMALL;
        }
        if (!cipherBytes.empty())
        {
            std::memcpy(outputBuffer, cipherBytes.data(), cipherBytes.size());
        }
        *outputBufferSize = static_cast<int>(cipherBytes.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::EncryptStringArmored(const char* inputString, const int inputStringSize, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (impl_->peerKeyIds.empty())
        {
            return INVALID_ARGUMENT;
        }
        std::vector<std::string> recipients(1, impl_->peerKeyIds.back());
        std::vector<unsigned char> armoredBytes;
        const int status = impl_->encryptCommon(reinterpret_cast<const unsigned char*>(inputString), inputStringSize, recipients, true, armoredBytes);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armoredBytes.size()))
        {
            *outputBufferSize = static_cast<int>(armoredBytes.size());
            return BUFFER_TOO_SMALL;
        }
        if (!armoredBytes.empty())
        {
            std::memcpy(outputBuffer, armoredBytes.data(), armoredBytes.size());
        }
        *outputBufferSize = static_cast<int>(armoredBytes.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::EncryptBufferMultiRecipient( const unsigned char* inputBuffer, const int inputBufferSize,
                                                   const char* const* recipientKeyIds, const int recipientCount,
                                                   const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr || recipientKeyIds == nullptr || recipientCount <= 0)
        {
            return INVALID_ARGUMENT;
        }
        std::vector<std::string> recipients;
        recipients.reserve(static_cast<std::size_t>(recipientCount));
        for (int i = 0; i < recipientCount; ++i)
        {
            if (recipientKeyIds[i] == nullptr)
            {
                return INVALID_ARGUMENT;
            }
            recipients.push_back(recipientKeyIds[i]);
        }
        std::vector<unsigned char> cipherBytes;
        const int status = impl_->encryptCommon(inputBuffer, inputBufferSize, recipients, false, cipherBytes);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(cipherBytes.size()))
        {
            *outputBufferSize = static_cast<int>(cipherBytes.size());
            return BUFFER_TOO_SMALL;
        }
        if (!cipherBytes.empty())
        {
            std::memcpy(outputBuffer, cipherBytes.data(), cipherBytes.size());
        }
        *outputBufferSize = static_cast<int>(cipherBytes.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::EncryptStringArmoredMultiRecipient( const char* inputString, const int inputStringSize,
                                                          const char* const* recipientKeyIds, const int recipientCount,
                                                          const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr || recipientKeyIds == nullptr || recipientCount <= 0)
        {
            return INVALID_ARGUMENT;
        }
        std::vector<std::string> recipients;
        recipients.reserve(static_cast<std::size_t>(recipientCount));
        for (int i = 0; i < recipientCount; ++i)
        {
            if (recipientKeyIds[i] == nullptr)
            {
                return INVALID_ARGUMENT;
            }
            recipients.push_back(recipientKeyIds[i]);
        }
        std::vector<unsigned char> armoredBytes;
        const int status = impl_->encryptCommon(reinterpret_cast<const unsigned char*>(inputString), inputStringSize, recipients, true, armoredBytes);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armoredBytes.size()))
        {
            *outputBufferSize = static_cast<int>(armoredBytes.size());
            return BUFFER_TOO_SMALL;
        }
        if (!armoredBytes.empty())
        {
            std::memcpy(outputBuffer, armoredBytes.data(), armoredBytes.size());
        }
        *outputBufferSize = static_cast<int>(armoredBytes.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::DecryptBuffer( const char* password, const int passwordSize,
                                     const unsigned char* inputBuffer, const int inputBufferSize,
                                     const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        std::vector<unsigned char> plaintext;
        const int status = impl_->decryptCommon(password, passwordSize, inputBuffer, inputBufferSize, ".gpg", plaintext);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(plaintext.size()))
        {
            *outputBufferSize = static_cast<int>(plaintext.size());
            return BUFFER_TOO_SMALL;
        }
        if (!plaintext.empty())
        {
            std::memcpy(outputBuffer, plaintext.data(), plaintext.size());
        }
        *outputBufferSize = static_cast<int>(plaintext.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::DecryptStringArmored( const char* password, const int passwordSize,
                                            const char* inputString, const int inputStringSize,
                                            const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        std::vector<unsigned char> plaintext;
        const int status = impl_->decryptCommon(password, passwordSize, reinterpret_cast<const unsigned char*>(inputString), inputStringSize, ".asc", plaintext);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(plaintext.size()))
        {
            *outputBufferSize = static_cast<int>(plaintext.size());
            return BUFFER_TOO_SMALL;
        }
        if (!plaintext.empty())
        {
            std::memcpy(outputBuffer, plaintext.data(), plaintext.size());
        }
        *outputBufferSize = static_cast<int>(plaintext.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::SignBuffer( const char* password, const int passwordSize,
                                  const unsigned char* inputBuffer, const int inputBufferSize,
                                  const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        std::vector<unsigned char> signature;
        const int status = impl_->signCommon(password, passwordSize, inputBuffer, inputBufferSize, signature);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(signature.size()))
        {
            *outputBufferSize = static_cast<int>(signature.size());
            return BUFFER_TOO_SMALL;
        }
        if (!signature.empty())
        {
            std::memcpy(outputBuffer, signature.data(), signature.size());
        }
        *outputBufferSize = static_cast<int>(signature.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::VerifyBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                                    const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid)
{
    try
    {
        if (!impl_)
        {
            return INVALID_ARGUMENT;
        }
        return impl_->verifyDetachedCommon(inputBuffer, inputBufferSize, signatureBuffer, signatureBufferSize, isValid);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::ClearSignString( const char* password, const int passwordSize,
                                       const char* inputString, const int inputStringSize,
                                       const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        std::string armored;
        const int status = impl_->clearSignCommon(password, passwordSize, inputString, inputStringSize, armored);
        if (status != NO_ERROR)
        {
            return status;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armored.size()))
        {
            *outputBufferSize = static_cast<int>(armored.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, armored.data(), armored.size());
        *outputBufferSize = static_cast<int>(armored.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::VerifyClearSignedString(const char* clearSignedString, const int clearSignedStringSize, bool* isValid)
{
    try
    {
        if (!impl_)
        {
            return INVALID_ARGUMENT;
        }
        return impl_->verifyClearSignedCommon(clearSignedString, clearSignedStringSize, isValid);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::EncryptFile(const char* inputFilePath, const char* outputFilePath, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || inputFilePath == nullptr || outputFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (impl_->peerKeyIds.empty())
        {
            return INVALID_ARGUMENT;
        }
        if (!impl_->gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!impl_->homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }
        if (!fileExistsUtf8(inputFilePath))
        {
            return FILE_IO_ERROR;
        }
        if (onProgress != nullptr && !onProgress(0, 0, 0.0, progressUserData))
        {
            return OPERATION_CANCELLED;
        }

        std::vector<std::string> args = impl_->baseArgs();
        args.push_back("--trust-model");
        args.push_back("always");
        args.push_back("-r");
        args.push_back(impl_->peerKeyIds.back());
        args.push_back("--output");
        args.push_back(outputFilePath);
        args.push_back("--encrypt");
        args.push_back(inputFilePath);

        const GpgProcessResult result = runGpgProcess(args, std::string());
        if (!result.started || result.exitCode != 0)
        {
            return UNEXPECTED_ERROR;
        }

        if (onProgress != nullptr)
        {
            onProgress(1, 1, 100.0, progressUserData);
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::DecryptFile( const char* password, const int passwordSize,
                                   const char* inputFilePath, const char* outputFilePath,
                                   ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || password == nullptr || passwordSize <= 0 || inputFilePath == nullptr || outputFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!impl_->ownKeyGenerated)
        {
            return INVALID_ARGUMENT;
        }
        if (!impl_->gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!impl_->homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }
        if (!fileExistsUtf8(inputFilePath))
        {
            return FILE_IO_ERROR;
        }
        if (onProgress != nullptr && !onProgress(0, 0, 0.0, progressUserData))
        {
            return OPERATION_CANCELLED;
        }

        std::vector<std::string> args = impl_->baseArgs();
        args.push_back("--pinentry-mode");
        args.push_back("loopback");
        args.push_back("--passphrase-fd");
        args.push_back("0");
        args.push_back("--output");
        args.push_back(outputFilePath);
        args.push_back("--decrypt");
        args.push_back(inputFilePath);

        std::string stdinData(password, static_cast<std::size_t>(passwordSize));
        stdinData.push_back('\n');

        const GpgProcessResult result = runGpgProcess(args, stdinData);
        if (!result.started || result.exitCode != 0)
        {
            return INVALID_DATA;
        }

        if (onProgress != nullptr)
        {
            onProgress(1, 1, 100.0, progressUserData);
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::SignFile( const char* password, const int passwordSize,
                                const char* inputFilePath, const char* signatureFilePath,
                                ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || password == nullptr || passwordSize <= 0 || inputFilePath == nullptr || signatureFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!impl_->ownKeyGenerated)
        {
            return INVALID_ARGUMENT;
        }
        if (!impl_->gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!impl_->homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }
        if (!fileExistsUtf8(inputFilePath))
        {
            return FILE_IO_ERROR;
        }
        if (onProgress != nullptr && !onProgress(0, 0, 0.0, progressUserData))
        {
            return OPERATION_CANCELLED;
        }

        std::vector<std::string> args = impl_->baseArgs();
        args.push_back("--pinentry-mode");
        args.push_back("loopback");
        args.push_back("--passphrase-fd");
        args.push_back("0");
        args.push_back("--local-user");
        args.push_back(impl_->ownKeyId);
        args.push_back("--output");
        args.push_back(signatureFilePath);
        args.push_back("--detach-sign");
        args.push_back(inputFilePath);

        std::string stdinData(password, static_cast<std::size_t>(passwordSize));
        stdinData.push_back('\n');

        const GpgProcessResult result = runGpgProcess(args, stdinData);
        if (!result.started || result.exitCode != 0)
        {
            return UNEXPECTED_ERROR;
        }

        if (onProgress != nullptr)
        {
            onProgress(1, 1, 100.0, progressUserData);
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngineWrapper::VerifyFile( const char* inputFilePath, const char* signatureFilePath,
                                  bool* isValid, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || inputFilePath == nullptr || signatureFilePath == nullptr || isValid == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (impl_->peerKeyIds.empty())
        {
            return INVALID_ARGUMENT;
        }
        if (!impl_->gpgFound)
        {
            return NOT_IMPLEMENTED;
        }
        if (!impl_->homeDirReady)
        {
            return UNEXPECTED_ERROR;
        }
        if (!fileExistsUtf8(inputFilePath) || !fileExistsUtf8(signatureFilePath))
        {
            return FILE_IO_ERROR;
        }
        if (onProgress != nullptr && !onProgress(0, 0, 0.0, progressUserData))
        {
            return OPERATION_CANCELLED;
        }

        std::vector<std::string> args = impl_->baseArgs();
        args.push_back("--verify");
        args.push_back(signatureFilePath);
        args.push_back(inputFilePath);

        const GpgProcessResult result = runGpgProcess(args, std::string());
        if (!result.started)
        {
            return UNEXPECTED_ERROR;
        }

        *isValid = (result.exitCode == 0);

        if (onProgress != nullptr)
        {
            onProgress(1, 1, 100.0, progressUserData);
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

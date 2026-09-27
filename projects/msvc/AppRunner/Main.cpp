// AppRunner: a thin subprocess test harness, NOT a direct SDK consumer. Spawns AppBuilder.exe (or,
// once a later phase gives them the same CLI, DllRunner.exe/LibRunner.exe) as a child process,
// forwarding its own command-line args through unchanged, and echoes back the child's combined
// stdout+stderr and exit code. See the AppRunner CLI harness plan for the full multi-phase design.
//
// The command-line quoting/CreateProcessW/pipe-redirection code below is an ADAPTED local copy of
// src/Pgp/PgpEngineWrapper.cpp's own quoteWindowsArgument/buildCommandLine/runGpgProcess (generalized
// to spawn an arbitrary exe path instead of a hardcoded "gpg.exe") -- kept local rather than
// extracted into a shared header, since it originated as .cpp-local code there too.

#include <iostream>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>

namespace
{

// ================================================================================================
// UTF-8 <-> UTF-16 conversion, same reasoning as PgpEngineWrapper.cpp's own helpers: command-line
// arguments and file paths are UTF-8 (Rules.md convention); CreateProcessW/plain `main()` argv need
// UTF-16/ANSI respectively, so real Unicode argv is fetched via GetCommandLineW+CommandLineToArgvW
// and converted to UTF-8 explicitly rather than trusting `main(int, char**)`'s ANSI-codepage argv.
// ================================================================================================

std::vector<std::string> getUtf8CommandLineArgs()
{
    std::vector<std::string> result;
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argvW == nullptr)
    {
        return result;
    }

    for (int i = 1; i < argc; ++i)
    {
        const int utf8Size = WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, nullptr, 0, nullptr, nullptr);
        if (utf8Size <= 0)
        {
            continue;
        }
        std::vector<char> buffer(static_cast<std::size_t>(utf8Size));
        WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, buffer.data(), utf8Size, nullptr, nullptr);
        result.emplace_back(buffer.data());
    }

    LocalFree(argvW);
    return result;
}
// -----------------------------------------------------------------------------

bool utf8ToWide(const std::string& utf8Text, std::wstring& wideTextOut)
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
// -----------------------------------------------------------------------------

// Windows (not cmd.exe) command-line argument quoting -- CreateProcessW is invoked directly, no
// cmd.exe in between, so this is the only quoting rule that matters.
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
// stdio pipes (stdout and stderr share one pipe, so callers see the child's combined output the same
// way a "2>&1" shell redirection would). No cmd.exe involved anywhere.
// ================================================================================================

struct ChildProcessResult
{
    bool started;
    DWORD exitCode;
    std::string output;

    ChildProcessResult() : started(false), exitCode(static_cast<DWORD>(-1)) {}
};
// -----------------------------------------------------------------------------

ChildProcessResult runChildProcess(const std::vector<std::string>& argv)
{
    ChildProcessResult result;
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

// AppBuilder/AppRunner/DllRunner/LibRunner all land in the same output directory
// (projects/msvc/All/<Platform>/<Configuration>/), so the target exe is resolved relative to
// AppRunner's own path rather than any hardcoded/relative-to-cwd assumption.
std::string getSiblingExePath(const char* targetExeName)
{
    wchar_t selfPath[MAX_PATH];
    const DWORD selfPathLen = GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    if (selfPathLen == 0 || selfPathLen >= MAX_PATH)
    {
        return std::string();
    }

    const std::wstring selfPathStr(selfPath, selfPathLen);
    const std::wstring::size_type lastSlash = selfPathStr.find_last_of(L"\\/");
    const std::wstring directory = (lastSlash != std::wstring::npos) ? selfPathStr.substr(0, lastSlash + 1) : std::wstring();

    std::wstring targetNameWide;
    for (const char* p = targetExeName; *p != '\0'; ++p)
    {
        targetNameWide.push_back(static_cast<wchar_t>(*p));
    }
    const std::wstring fullPathWide = directory + targetNameWide;

    const int utf8Size = WideCharToMultiByte(CP_UTF8, 0, fullPathWide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Size <= 0)
    {
        return std::string();
    }
    std::vector<char> buffer(static_cast<std::size_t>(utf8Size));
    WideCharToMultiByte(CP_UTF8, 0, fullPathWide.c_str(), -1, buffer.data(), utf8Size, nullptr, nullptr);
    return std::string(buffer.data());
}
// -----------------------------------------------------------------------------

// Strips a single trailing \r\n or \n (runChildProcess's captured output always has one, since every
// -action prints via std::endl) -- needed before feeding one example's output as the next example's
// -input.
std::string stripTrailingNewline(const std::string& text)
{
    std::string result = text;
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
    {
        result.pop_back();
    }
    return result;
}
// -----------------------------------------------------------------------------

void printExampleHeader(const std::string& exeName, const std::vector<std::string>& displayArgs)
{
    std::cout << "--- " << exeName;
    for (std::size_t i = 0; i < displayArgs.size(); ++i)
    {
        std::cout << " " << displayArgs[i];
    }
    std::cout << " ---" << std::endl;
}
// -----------------------------------------------------------------------------

// Runs targetExeName with displayArgs (both shown in the header and actually passed to the child),
// prints the child's output, and returns it (trimmed) so callers can chain one example's output into
// the next example's -input, the same way a human would copy/paste between two separate invocations.
std::string runExample(const char* targetExeName, const std::vector<std::string>& displayArgs)
{
    printExampleHeader(targetExeName, displayArgs);

    const std::string exePath = getSiblingExePath(targetExeName);
    std::vector<std::string> childArgv;
    childArgv.push_back(exePath);
    for (std::size_t i = 0; i < displayArgs.size(); ++i)
    {
        childArgv.push_back(displayArgs[i]);
    }

    const ChildProcessResult result = runChildProcess(childArgv);
    if (!result.started)
    {
        std::cerr << "  (failed to start " << targetExeName << ")" << std::endl;
        return std::string();
    }

    std::cout << result.output;
    std::cout << "  (exit code: " << result.exitCode << ")" << std::endl << std::endl;
    return stripTrailingNewline(result.output);
}
// -----------------------------------------------------------------------------

void printSectionHeader(const std::string& title)
{
    std::cout << std::endl << "## " << title << std::endl;
}
// -----------------------------------------------------------------------------

// Triggered by `AppRunner.exe -examples`: runs a wide variety of real CLI usage scenarios, grouped by
// what they demonstrate, chaining real output between calls wherever that proves something (a
// two-separate-invocations round trip, cross-target format compatibility) rather than just describing
// it. Every example actually spawns the target exe via runExample -- nothing here is simulated.
void runUsageExamples()
{
    std::cout << "=== AppRunner kullanim ornekleri ===" << std::endl;

    printSectionHeader("1) version -- her 3 hedefte de calisiyor");
    runExample("AppBuilder.exe", { "-action", "version" });
    runExample("DllRunner.exe", { "-action", "version" });
    runExample("LibRunner.exe", { "-action", "version" });

    printSectionHeader("2) hash -- farkli girdi turleri (bos, ASCII, Turkce/UTF-8)");
    runExample("AppBuilder.exe", { "-action", "hash", "-input", "" });
    runExample("AppBuilder.exe", { "-action", "hash", "-input", "hello world" });
    runExample("AppBuilder.exe", { "-action", "hash", "-input", "Merhaba dunya, sifreleme calisiyor!" });

    printSectionHeader("3) encrypt-string / decrypt-string -- AYNI hedefte, iki ayri invocation arasi round-trip");
    const std::string cipherText = runExample( "AppBuilder.exe",
                                               { "-action", "encrypt-string", "-password", "s3cr3t", "-input", "hello world" });
    runExample("AppBuilder.exe", { "-action", "decrypt-string", "-password", "s3cr3t", "-input", cipherText });

    printSectionHeader("4) encrypt-string / decrypt-string -- FARKLI hedefler arasi (sifreleme formati uyumlulugu kaniti: DllRunner ile sifrele, LibRunner ile coz)");
    const std::string cipherTextCrossTarget = runExample( "DllRunner.exe",
                                                          { "-action", "encrypt-string", "-password", "cross-target", "-input", "farkli hedeflerde sifreleniyor" });
    runExample("LibRunner.exe", { "-action", "decrypt-string", "-password", "cross-target", "-input", cipherTextCrossTarget });

    printSectionHeader("5) decrypt-string -- YANLIS parola (hata beklenen senaryo)");
    runExample("AppBuilder.exe", { "-action", "decrypt-string", "-password", "yanlis-parola", "-input", cipherText });

    printSectionHeader("6) pgp-roundtrip -- varsayilan userid, ozel userid + Turkce mesaj, her 3 hedef");
    runExample("AppBuilder.exe", { "-action", "pgp-roundtrip", "-password", "s3cr3t", "-message", "merhaba" });
    runExample( "AppBuilder.exe",
               { "-action", "pgp-roundtrip", "-userid", "Ayse Yilmaz <ayse@example.com>", "-password", "farkli-parola",
                "-message", "Turkce karakterler: sicak cay iciyorum" });
    runExample("DllRunner.exe", { "-action", "pgp-roundtrip", "-password", "s3cr3t", "-message", "DLL uzerinden PGP" });
    runExample("LibRunner.exe", { "-action", "pgp-roundtrip", "-password", "s3cr3t", "-message", "static lib uzerinden PGP" });

    printSectionHeader("7) hata durumlari -- bilinmeyen/eksik -action (exit code != 0 bekleniyor)");
    runExample("AppBuilder.exe", { "-action", "bogus-action" });
    runExample("AppBuilder.exe", { "-userid", "bu bir action degil" });

    std::cout << "=== tamamlandi ===" << std::endl;
}
// -----------------------------------------------------------------------------

} // anonymous namespace

int main()
{
    const std::vector<std::string> args = getUtf8CommandLineArgs();

    // -examples runs the whole usage-example sequence and exits -- takes no other arguments.
    for (std::size_t i = 0; i < args.size(); ++i)
    {
        if (args[i] == "-examples" || args[i] == "--examples")
        {
            runUsageExamples();
            return 0;
        }
    }

    // -target selects which sibling exe to spawn -- consumed here, never forwarded to the child.
    // AppBuilder/DllRunner/LibRunner all have the identical CLI action set now (version/hash/
    // encrypt-string/decrypt-string/pgp-roundtrip).
    std::string targetName = "appbuilder";
    std::vector<std::string> forwardedArgs;
    for (std::size_t i = 0; i < args.size(); ++i)
    {
        if ((args[i] == "-target" || args[i] == "--target") && i + 1 < args.size())
        {
            targetName = args[i + 1];
            ++i;
            continue;
        }
        forwardedArgs.push_back(args[i]);
    }

    const char* targetExeName = nullptr;
    if (targetName == "appbuilder")
    {
        targetExeName = "AppBuilder.exe";
    }
    else if (targetName == "dllrunner")
    {
        targetExeName = "DllRunner.exe";
    }
    else if (targetName == "librunner")
    {
        targetExeName = "LibRunner.exe";
    }
    else
    {
        std::cerr << "AppRunner: unknown -target '" << targetName << "', expected appbuilder/dllrunner/librunner" << std::endl;
        return 2;
    }

    const std::string childExePath = getSiblingExePath(targetExeName);
    if (childExePath.empty())
    {
        std::cerr << "AppRunner: could not resolve path to " << targetExeName << std::endl;
        return 3;
    }

    std::vector<std::string> childArgv;
    childArgv.push_back(childExePath);
    for (std::size_t i = 0; i < forwardedArgs.size(); ++i)
    {
        childArgv.push_back(forwardedArgs[i]);
    }

    const ChildProcessResult result = runChildProcess(childArgv);
    if (!result.started)
    {
        std::cerr << "AppRunner: failed to start " << childExePath << std::endl;
        return 4;
    }

    std::cout << result.output;
    return static_cast<int>(result.exitCode);
}

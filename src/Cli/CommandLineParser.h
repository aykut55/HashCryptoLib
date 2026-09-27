#ifndef AYCRYPTO_COMMAND_LINE_PARSER_H
#define AYCRYPTO_COMMAND_LINE_PARSER_H

#include <string>
#include <vector>

namespace CryptoApiNS
{

// EXE-side helper only -- never crosses the DLL ABI boundary (only used inside Main.cpp of
// AppBuilder/AppRunner/DllRunner/LibRunner), so its public signature is free to use std::string/
// std::vector directly. argv passed to Parse() must already be UTF-8 (Rules.md convention);
// callers on Windows get real Unicode argv via GetCommandLineW + CommandLineToArgvW and convert
// each argument to UTF-8 before calling Parse -- plain `main(int, char**)` argv is ANSI/OEM
// codepage, not UTF-8, and is not what this class expects.
//
// Recognizes "-name value" and "--name value" (leading dashes stripped and treated identically).
// A name with no following value, or immediately followed by another option, is a boolean flag.
// Bare tokens with no leading dash are positional arguments.
class CCommandLineParser
{
public:
    virtual ~CCommandLineParser();
             CCommandLineParser();

    bool Parse(const std::vector<std::string>& utf8Argv);

    std::string GetString(const std::string& name, const std::string& defaultValue) const;
    int GetInt(const std::string& name, const int defaultValue) const;
    bool HasFlag(const std::string& name) const;

    int GetPositionalCount(void) const;
    std::string GetPositional(const int index) const;

protected:

private:
    std::vector<std::pair<std::string, std::string>> options_;
    std::vector<std::string> positionals_;
};

} // namespace CryptoApiNS

#endif

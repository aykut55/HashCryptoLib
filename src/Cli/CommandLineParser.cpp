#include "CommandLineParser.h"

#include <cctype>
#include <cstdlib>

namespace
{

// A token is an option name (e.g. "-input"/"--input") only when a letter immediately follows its
// leading dash(es) -- NOT any token that merely starts with '-'. This matters because PGP-armored
// text (this parser's own values in practice, e.g. "-----BEGIN PGP MESSAGE-----...") also starts
// with dashes; without this distinction, an armored block passed as an option's value would be
// mistaken for the start of a new option, leaving the real option valueless and the armored block
// stranded as a positional argument instead.
bool looksLikeOptionToken(const std::string& token)
{
    if (token.size() < 2 || token[0] != '-')
    {
        return false;
    }
    std::size_t nameStart = 1;
    if (token[1] == '-')
    {
        nameStart = 2;
    }
    if (nameStart >= token.size())
    {
        return false;
    }
    return std::isalpha(static_cast<unsigned char>(token[nameStart])) != 0;
}
// -----------------------------------------------------------------------------

} // anonymous namespace

namespace CryptoApiNS
{

CCommandLineParser::~CCommandLineParser()
{
}
// -----------------------------------------------------------------------------

CCommandLineParser::CCommandLineParser()
{
}
// -----------------------------------------------------------------------------

bool CCommandLineParser::Parse(const std::vector<std::string>& utf8Argv)
{
    try
    {
        options_.clear();
        positionals_.clear();

        for (std::size_t i = 0; i < utf8Argv.size(); ++i)
        {
            const std::string& token = utf8Argv[i];
            if (!looksLikeOptionToken(token))
            {
                positionals_.push_back(token);
                continue;
            }

            const std::size_t nameStart = (token[1] == '-') ? 2 : 1;
            const std::string name = token.substr(nameStart);

            if (i + 1 < utf8Argv.size() && !looksLikeOptionToken(utf8Argv[i + 1]))
            {
                options_.emplace_back(name, utf8Argv[i + 1]);
                ++i;
            }
            else
            {
                options_.emplace_back(name, std::string());
            }
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::string CCommandLineParser::GetString(const std::string& name, const std::string& defaultValue) const
{
    try
    {
        for (const auto& option : options_)
        {
            if (option.first == name)
            {
                return option.second;
            }
        }
        return defaultValue;
    }
    catch (...)
    {
        return defaultValue;
    }
}
// -----------------------------------------------------------------------------

int CCommandLineParser::GetInt(const std::string& name, const int defaultValue) const
{
    try
    {
        for (const auto& option : options_)
        {
            if (option.first == name)
            {
                if (option.second.empty())
                {
                    return defaultValue;
                }
                return std::atoi(option.second.c_str());
            }
        }
        return defaultValue;
    }
    catch (...)
    {
        return defaultValue;
    }
}
// -----------------------------------------------------------------------------

bool CCommandLineParser::HasFlag(const std::string& name) const
{
    try
    {
        for (const auto& option : options_)
        {
            if (option.first == name)
            {
                return true;
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

int CCommandLineParser::GetPositionalCount(void) const
{
    try
    {
        return static_cast<int>(positionals_.size());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::string CCommandLineParser::GetPositional(const int index) const
{
    try
    {
        if (index < 0 || static_cast<std::size_t>(index) >= positionals_.size())
        {
            return std::string();
        }
        return positionals_[static_cast<std::size_t>(index)];
    }
    catch (...)
    {
        return std::string();
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

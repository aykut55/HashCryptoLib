#include "CommandLineParser.h"

#include <cstdlib>

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
            if (token.empty() || token[0] != '-')
            {
                positionals_.push_back(token);
                continue;
            }

            std::size_t nameStart = 1;
            if (token.size() > 1 && token[1] == '-')
            {
                nameStart = 2;
            }
            const std::string name = token.substr(nameStart);

            if (i + 1 < utf8Argv.size() && !utf8Argv[i + 1].empty() && utf8Argv[i + 1][0] != '-')
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

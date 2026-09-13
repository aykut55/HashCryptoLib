#include "Utils.h"

#include "../CryptoApi.h"
#include "../Defiinions/Definitions.h"

#include <string>

namespace CryptoApiNS
{

CUtils::~CUtils()
{
}
// -----------------------------------------------------------------------------

CUtils::CUtils()
{
}
// -----------------------------------------------------------------------------

const char* CUtils::FormatBuildDate(void)
{
    try
    {
        static const char* monthNames[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        static const char* monthNumbers[] = {
            "01", "02", "03", "04", "05", "06",
            "07", "08", "09", "10", "11", "12"
        };

        const std::string rawDate = CRYPTOAPI_BUILD_DATE_RAW;
        std::string month = "00";

        for (unsigned int index = 0; index < 12; ++index)
        {
            if (rawDate.compare(0, 3, monthNames[index]) == 0)
            {
                month = monthNumbers[index];
                break;
            }
        }

        std::string formattedDate = rawDate.substr(7, 4) + "." + month + ".";
        formattedDate += rawDate[4] == ' ' ? '0' : rawDate[4];
        formattedDate += rawDate[5];

        static const std::string buildDate = formattedDate;
        return buildDate.c_str();
    }
    catch (...)
    {
        return "";
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

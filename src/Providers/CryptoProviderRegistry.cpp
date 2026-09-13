#include "CryptoProviderRegistry.h"

#include "Providers/MicrosoftProvider/MicrosoftProviderFactory.h"
#include "Providers/CryptoPPProvider/CryptoPPProviderFactory.h"
#include "Providers/BotanProvider/BotanProviderFactory.h"
#include "Providers/OpenSslProvider/OpenSslProviderFactory.h"

namespace CryptoApiNS
{

std::unique_ptr<ICryptoProviderFactory> CreateProviderFactory(const ProviderKind kind)
{
    try
    {
        switch (kind)
        {
            case PROVIDER_MICROSOFT:
                return std::unique_ptr<ICryptoProviderFactory>(new CMicrosoftProviderFactory());
            case PROVIDER_CRYPTOPP:
                return std::unique_ptr<ICryptoProviderFactory>(new CCryptoPPProviderFactory());
            case PROVIDER_BOTAN:
                return std::unique_ptr<ICryptoProviderFactory>(new CBotanProviderFactory());
            case PROVIDER_OPENSSL:
                return std::unique_ptr<ICryptoProviderFactory>(new COpenSslProviderFactory());
            default:
                return nullptr;
        }
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#include "BotanProviderFactory.h"
#include "BotanProvider.h"

namespace CryptoApiNS
{

CBotanProviderFactory::~CBotanProviderFactory()
{
}
// -----------------------------------------------------------------------------

CBotanProviderFactory::CBotanProviderFactory()
{
}
// -----------------------------------------------------------------------------

bool CBotanProviderFactory::SupportsAeadAlgorithm(const AeadAlgorithm algorithm) const
{
    try
    {
        CBotanProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAeadCipher> CBotanProviderFactory::CreateAeadCipher(const AeadAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CBotanProvider> provider(new CBotanProvider());
        if (!provider->Initialize() || !provider->SelectAlgorithm(algorithm))
        {
            return nullptr;
        }

        return provider;
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProviderFactory::SupportsLegacyAlgorithm(const LegacySymmetricAlgorithm algorithm) const
{
    try
    {
        CBotanProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<ILegacyCipher> CBotanProviderFactory::CreateLegacyCipher(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CBotanProvider> provider(new CBotanProvider());
        if (!provider->Initialize() || !provider->SelectAlgorithm(algorithm))
        {
            return nullptr;
        }

        return provider;
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IRandomSource> CBotanProviderFactory::CreateRandomSource()
{
    try
    {
        return std::unique_ptr<IRandomSource>(new CBotanProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IKeyDerivation> CBotanProviderFactory::CreateKeyDerivation()
{
    try
    {
        return std::unique_ptr<IKeyDerivation>(new CBotanProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProviderFactory::SupportsAsymmetricAlgorithm(const AsymmetricAlgorithm algorithm) const
{
    (void)algorithm;
    return false; // Not wired yet; Botan does have RSA, just not implemented here.
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAsymmetricCipher> CBotanProviderFactory::CreateAsymmetricCipher(const AsymmetricAlgorithm algorithm)
{
    (void)algorithm;
    return nullptr;
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

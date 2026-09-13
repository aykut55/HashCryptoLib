#include "CryptoPPProviderFactory.h"
#include "CryptoPPProvider.h"

namespace CryptoApiNS
{

CCryptoPPProviderFactory::~CCryptoPPProviderFactory()
{
}
// -----------------------------------------------------------------------------

CCryptoPPProviderFactory::CCryptoPPProviderFactory()
{
}
// -----------------------------------------------------------------------------

bool CCryptoPPProviderFactory::SupportsAeadAlgorithm(const AeadAlgorithm algorithm) const
{
    try
    {
        CCryptoPPProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAeadCipher> CCryptoPPProviderFactory::CreateAeadCipher(const AeadAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CCryptoPPProvider> provider(new CCryptoPPProvider());
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

bool CCryptoPPProviderFactory::SupportsLegacyAlgorithm(const LegacySymmetricAlgorithm algorithm) const
{
    try
    {
        CCryptoPPProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<ILegacyCipher> CCryptoPPProviderFactory::CreateLegacyCipher(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CCryptoPPProvider> provider(new CCryptoPPProvider());
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

std::unique_ptr<IRandomSource> CCryptoPPProviderFactory::CreateRandomSource()
{
    try
    {
        return std::unique_ptr<IRandomSource>(new CCryptoPPProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProviderFactory::SupportsAsymmetricAlgorithm(const AsymmetricAlgorithm algorithm) const
{
    (void)algorithm;
    return false; // Not wired yet; CryptoPP does have RSA, just not implemented here.
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAsymmetricCipher> CCryptoPPProviderFactory::CreateAsymmetricCipher(const AsymmetricAlgorithm algorithm)
{
    (void)algorithm;
    return nullptr;
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

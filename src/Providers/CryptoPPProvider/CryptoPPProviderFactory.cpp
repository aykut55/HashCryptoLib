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

bool CCryptoPPProviderFactory::SupportsRandomAlgorithm(const RandomAlgorithm algorithm) const
{
    try
    {
        CCryptoPPProvider provider;
        return provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IRandomSource> CCryptoPPProviderFactory::CreateRandomSource(const RandomAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CCryptoPPProvider> provider(new CCryptoPPProvider());
        if (!provider->SelectAlgorithm(algorithm))
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

std::unique_ptr<IKeyDerivation> CCryptoPPProviderFactory::CreateKeyDerivation()
{
    try
    {
        return std::unique_ptr<IKeyDerivation>(new CCryptoPPProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProviderFactory::SupportsAsymmetricAlgorithm(const AsymmetricAlgorithm algorithm) const
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

std::unique_ptr<IAsymmetricCipher> CCryptoPPProviderFactory::CreateAsymmetricCipher(const AsymmetricAlgorithm algorithm)
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

std::unique_ptr<IMacService> CCryptoPPProviderFactory::CreateMacService()
{
    try
    {
        return std::unique_ptr<IMacService>(new CCryptoPPProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProviderFactory::SupportsHashAlgorithm(const HashAlgorithm algorithm) const
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

std::unique_ptr<IHashService> CCryptoPPProviderFactory::CreateHashService(const HashAlgorithm algorithm)
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

bool CCryptoPPProviderFactory::SupportsSignatureAlgorithm(const SignatureAlgorithm algorithm) const
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

std::unique_ptr<ISignatureEngine> CCryptoPPProviderFactory::CreateSignatureEngine(const SignatureAlgorithm algorithm)
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

bool CCryptoPPProviderFactory::SupportsKeyAgreementAlgorithm(const KeyAgreementAlgorithm algorithm) const
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

std::unique_ptr<IKeyAgreementService> CCryptoPPProviderFactory::CreateKeyAgreementEngine(const KeyAgreementAlgorithm algorithm)
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

} // namespace CryptoApiNS

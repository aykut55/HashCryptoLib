#include "MicrosoftProviderFactory.h"
#include "MicrosoftProvider.h"

namespace CryptoApiNS
{

CMicrosoftProviderFactory::~CMicrosoftProviderFactory()
{
}
// -----------------------------------------------------------------------------

CMicrosoftProviderFactory::CMicrosoftProviderFactory()
{
}
// -----------------------------------------------------------------------------

bool CMicrosoftProviderFactory::SupportsAeadAlgorithm(const AeadAlgorithm algorithm) const
{
    try
    {
        CMicrosoftProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAeadCipher> CMicrosoftProviderFactory::CreateAeadCipher(const AeadAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CMicrosoftProvider> provider(new CMicrosoftProvider());
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

bool CMicrosoftProviderFactory::SupportsLegacyAlgorithm(const LegacySymmetricAlgorithm algorithm) const
{
    try
    {
        CMicrosoftProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<ILegacyCipher> CMicrosoftProviderFactory::CreateLegacyCipher(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CMicrosoftProvider> provider(new CMicrosoftProvider());
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

std::unique_ptr<IRandomSource> CMicrosoftProviderFactory::CreateRandomSource()
{
    try
    {
        return std::unique_ptr<IRandomSource>(new CMicrosoftProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProviderFactory::SupportsRandomAlgorithm(const RandomAlgorithm algorithm) const
{
    try
    {
        CMicrosoftProvider provider;
        return provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IRandomSource> CMicrosoftProviderFactory::CreateRandomSource(const RandomAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CMicrosoftProvider> provider(new CMicrosoftProvider());
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

std::unique_ptr<IKeyDerivation> CMicrosoftProviderFactory::CreateKeyDerivation()
{
    try
    {
        return std::unique_ptr<IKeyDerivation>(new CMicrosoftProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProviderFactory::SupportsAsymmetricAlgorithm(const AsymmetricAlgorithm algorithm) const
{
    try
    {
        CMicrosoftProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAsymmetricCipher> CMicrosoftProviderFactory::CreateAsymmetricCipher(const AsymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CMicrosoftProvider> provider(new CMicrosoftProvider());
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

std::unique_ptr<IMacService> CMicrosoftProviderFactory::CreateMacService()
{
    try
    {
        return std::unique_ptr<IMacService>(new CMicrosoftProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProviderFactory::SupportsHashAlgorithm(const HashAlgorithm algorithm) const
{
    try
    {
        CMicrosoftProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IHashService> CMicrosoftProviderFactory::CreateHashService(const HashAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CMicrosoftProvider> provider(new CMicrosoftProvider());
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

bool CMicrosoftProviderFactory::SupportsSignatureAlgorithm(const SignatureAlgorithm algorithm) const
{
    try
    {
        CMicrosoftProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<ISignatureEngine> CMicrosoftProviderFactory::CreateSignatureEngine(const SignatureAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CMicrosoftProvider> provider(new CMicrosoftProvider());
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

bool CMicrosoftProviderFactory::SupportsKeyAgreementAlgorithm(const KeyAgreementAlgorithm algorithm) const
{
    try
    {
        CMicrosoftProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IKeyAgreementService> CMicrosoftProviderFactory::CreateKeyAgreementEngine(const KeyAgreementAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CMicrosoftProvider> provider(new CMicrosoftProvider());
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

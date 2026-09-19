#include "LibgcryptProviderFactory.h"
#include "LibgcryptProvider.h"

namespace CryptoApiNS
{

CLibgcryptProviderFactory::~CLibgcryptProviderFactory()
{
}
// -----------------------------------------------------------------------------

CLibgcryptProviderFactory::CLibgcryptProviderFactory()
{
}
// -----------------------------------------------------------------------------

bool CLibgcryptProviderFactory::SupportsAeadAlgorithm(const AeadAlgorithm algorithm) const
{
    try
    {
        CLibgcryptProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAeadCipher> CLibgcryptProviderFactory::CreateAeadCipher(const AeadAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CLibgcryptProvider> provider(new CLibgcryptProvider());
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

bool CLibgcryptProviderFactory::SupportsLegacyAlgorithm(const LegacySymmetricAlgorithm algorithm) const
{
    try
    {
        CLibgcryptProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<ILegacyCipher> CLibgcryptProviderFactory::CreateLegacyCipher(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CLibgcryptProvider> provider(new CLibgcryptProvider());
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

std::unique_ptr<IRandomSource> CLibgcryptProviderFactory::CreateRandomSource()
{
    try
    {
        return std::unique_ptr<IRandomSource>(new CLibgcryptProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProviderFactory::SupportsRandomAlgorithm(const RandomAlgorithm algorithm) const
{
    try
    {
        CLibgcryptProvider provider;
        return provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IRandomSource> CLibgcryptProviderFactory::CreateRandomSource(const RandomAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CLibgcryptProvider> provider(new CLibgcryptProvider());
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

std::unique_ptr<IKeyDerivation> CLibgcryptProviderFactory::CreateKeyDerivation()
{
    try
    {
        return std::unique_ptr<IKeyDerivation>(new CLibgcryptProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProviderFactory::SupportsAsymmetricAlgorithm(const AsymmetricAlgorithm algorithm) const
{
    try
    {
        CLibgcryptProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAsymmetricCipher> CLibgcryptProviderFactory::CreateAsymmetricCipher(const AsymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CLibgcryptProvider> provider(new CLibgcryptProvider());
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

std::unique_ptr<IMacService> CLibgcryptProviderFactory::CreateMacService()
{
    try
    {
        return std::unique_ptr<IMacService>(new CLibgcryptProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProviderFactory::SupportsHashAlgorithm(const HashAlgorithm algorithm) const
{
    try
    {
        CLibgcryptProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IHashService> CLibgcryptProviderFactory::CreateHashService(const HashAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CLibgcryptProvider> provider(new CLibgcryptProvider());
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

bool CLibgcryptProviderFactory::SupportsSignatureAlgorithm(const SignatureAlgorithm algorithm) const
{
    try
    {
        CLibgcryptProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<ISignatureEngine> CLibgcryptProviderFactory::CreateSignatureEngine(const SignatureAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CLibgcryptProvider> provider(new CLibgcryptProvider());
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

bool CLibgcryptProviderFactory::SupportsKeyAgreementAlgorithm(const KeyAgreementAlgorithm algorithm) const
{
    try
    {
        CLibgcryptProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IKeyAgreementService> CLibgcryptProviderFactory::CreateKeyAgreementEngine(const KeyAgreementAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<CLibgcryptProvider> provider(new CLibgcryptProvider());
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

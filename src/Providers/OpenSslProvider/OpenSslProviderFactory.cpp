#include "OpenSslProviderFactory.h"
#include "OpenSslProvider.h"

namespace CryptoApiNS
{

COpenSslProviderFactory::~COpenSslProviderFactory()
{
}
// -----------------------------------------------------------------------------

COpenSslProviderFactory::COpenSslProviderFactory()
{
}
// -----------------------------------------------------------------------------

bool COpenSslProviderFactory::SupportsAeadAlgorithm(const AeadAlgorithm algorithm) const
{
    try
    {
        COpenSslProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAeadCipher> COpenSslProviderFactory::CreateAeadCipher(const AeadAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<COpenSslProvider> provider(new COpenSslProvider());
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

bool COpenSslProviderFactory::SupportsLegacyAlgorithm(const LegacySymmetricAlgorithm algorithm) const
{
    try
    {
        COpenSslProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<ILegacyCipher> COpenSslProviderFactory::CreateLegacyCipher(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<COpenSslProvider> provider(new COpenSslProvider());
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

std::unique_ptr<IRandomSource> COpenSslProviderFactory::CreateRandomSource()
{
    try
    {
        return std::unique_ptr<IRandomSource>(new COpenSslProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IKeyDerivation> COpenSslProviderFactory::CreateKeyDerivation()
{
    try
    {
        return std::unique_ptr<IKeyDerivation>(new COpenSslProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProviderFactory::SupportsAsymmetricAlgorithm(const AsymmetricAlgorithm algorithm) const
{
    try
    {
        COpenSslProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IAsymmetricCipher> COpenSslProviderFactory::CreateAsymmetricCipher(const AsymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<COpenSslProvider> provider(new COpenSslProvider());
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

std::unique_ptr<IMacService> COpenSslProviderFactory::CreateMacService()
{
    try
    {
        return std::unique_ptr<IMacService>(new COpenSslProvider());
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProviderFactory::SupportsHashAlgorithm(const HashAlgorithm algorithm) const
{
    try
    {
        COpenSslProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IHashService> COpenSslProviderFactory::CreateHashService(const HashAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<COpenSslProvider> provider(new COpenSslProvider());
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

bool COpenSslProviderFactory::SupportsSignatureAlgorithm(const SignatureAlgorithm algorithm) const
{
    try
    {
        COpenSslProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<ISignatureEngine> COpenSslProviderFactory::CreateSignatureEngine(const SignatureAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<COpenSslProvider> provider(new COpenSslProvider());
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

bool COpenSslProviderFactory::SupportsKeyAgreementAlgorithm(const KeyAgreementAlgorithm algorithm) const
{
    try
    {
        COpenSslProvider provider;
        return provider.Initialize() && provider.SelectAlgorithm(algorithm);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::unique_ptr<IKeyAgreementService> COpenSslProviderFactory::CreateKeyAgreementEngine(const KeyAgreementAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<COpenSslProvider> provider(new COpenSslProvider());
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

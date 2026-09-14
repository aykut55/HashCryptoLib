#ifndef CRYPTOAPI_PROVIDERS_MICROSOFT_PROVIDER_FACTORY_H
#define CRYPTOAPI_PROVIDERS_MICROSOFT_PROVIDER_FACTORY_H

#include "Providers/CryptoProviderFactory.h"

namespace CryptoApiNS
{

class CMicrosoftProviderFactory : public ICryptoProviderFactory
{
public:
    virtual ~CMicrosoftProviderFactory();
             CMicrosoftProviderFactory();

    virtual bool SupportsAeadAlgorithm(const AeadAlgorithm algorithm) const;
    virtual std::unique_ptr<IAeadCipher> CreateAeadCipher(const AeadAlgorithm algorithm);

    virtual bool SupportsLegacyAlgorithm(const LegacySymmetricAlgorithm algorithm) const;
    virtual std::unique_ptr<ILegacyCipher> CreateLegacyCipher(const LegacySymmetricAlgorithm algorithm);

    virtual std::unique_ptr<IRandomSource> CreateRandomSource();

    virtual std::unique_ptr<IKeyDerivation> CreateKeyDerivation();

    virtual bool SupportsAsymmetricAlgorithm(const AsymmetricAlgorithm algorithm) const;
    virtual std::unique_ptr<IAsymmetricCipher> CreateAsymmetricCipher(const AsymmetricAlgorithm algorithm);

    virtual std::unique_ptr<IMacService> CreateMacService();

protected:

private:

};

} // namespace CryptoApiNS

#endif

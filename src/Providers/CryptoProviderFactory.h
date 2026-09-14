#ifndef CRYPTOAPI_PROVIDERS_CRYPTO_PROVIDER_FACTORY_H
#define CRYPTOAPI_PROVIDERS_CRYPTO_PROVIDER_FACTORY_H

#include "Providers/AeadCipher.h"
#include "Providers/AsymmetricCipher.h"
#include "Providers/KeyDerivation.h"
#include "Providers/LegacyCipher.h"
#include "Providers/ProviderTypes.h"
#include "Providers/RandomSource.h"

#include <memory>

namespace CryptoApiNS
{

// Abstract Factory: given a ProviderKind (see CreateProviderFactory() in
// CryptoProviderRegistry.h), produces IAeadCipher/ILegacyCipher instances already bound to a
// specific algorithm. Callers never need to know which underlying crypto library (CryptoPP,
// Botan, OpenSSL, Windows CNG) actually implements the returned instance.
class ICryptoProviderFactory
{
public:
    virtual ~ICryptoProviderFactory();
             ICryptoProviderFactory();

    virtual bool SupportsAeadAlgorithm(const AeadAlgorithm algorithm) const = 0;
    virtual std::unique_ptr<IAeadCipher> CreateAeadCipher(const AeadAlgorithm algorithm) = 0;

    virtual bool SupportsLegacyAlgorithm(const LegacySymmetricAlgorithm algorithm) const = 0;
    virtual std::unique_ptr<ILegacyCipher> CreateLegacyCipher(const LegacySymmetricAlgorithm algorithm) = 0;

    // Random sources are algorithm-independent (no SelectAlgorithm needed), used e.g. to supply
    // fresh per-chunk nonces to IAeadCipher::EncryptChunked.
    virtual std::unique_ptr<IRandomSource> CreateRandomSource() = 0;

    // Key derivation is algorithm-independent (no SelectAlgorithm needed), used to turn a
    // caller-supplied password into a key suitable for IAeadCipher::SetKey.
    virtual std::unique_ptr<IKeyDerivation> CreateKeyDerivation() = 0;

    // Not every provider implements asymmetric (public/private key-pair) crypto yet; providers
    // that don't must have SupportsAsymmetricAlgorithm() return false and CreateAsymmetricCipher()
    // return nullptr for every value, rather than omitting the methods.
    virtual bool SupportsAsymmetricAlgorithm(const AsymmetricAlgorithm algorithm) const = 0;
    virtual std::unique_ptr<IAsymmetricCipher> CreateAsymmetricCipher(const AsymmetricAlgorithm algorithm) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

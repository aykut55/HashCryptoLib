#ifndef CRYPTOAPI_PROVIDERS_CRYPTO_PROVIDER_REGISTRY_H
#define CRYPTOAPI_PROVIDERS_CRYPTO_PROVIDER_REGISTRY_H

#include "Providers/CryptoProviderFactory.h"
#include "Providers/ProviderTypes.h"

#include <memory>

namespace CryptoApiNS
{

// The single entry point calling code needs: given a ProviderKind, returns a factory that can
// create algorithm-specific IAeadCipher/ILegacyCipher instances for that provider. Swapping
// providers (e.g. PROVIDER_MICROSOFT -> PROVIDER_CRYPTOPP) is a single argument change at the
// call site; the rest of the calling code is unchanged since both factories implement the same
// ICryptoProviderFactory interface. Returns nullptr for an unrecognized ProviderKind.
std::unique_ptr<ICryptoProviderFactory> CreateProviderFactory(const ProviderKind kind);

} // namespace CryptoApiNS

#endif

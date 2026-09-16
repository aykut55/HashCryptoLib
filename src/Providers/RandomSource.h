#ifndef CRYPTOAPI_PROVIDERS_RANDOM_SOURCE_H
#define CRYPTOAPI_PROVIDERS_RANDOM_SOURCE_H

#include "Providers/ProviderTypes.h"

namespace CryptoApiNS
{

class IRandomSource
{
public:
    virtual ~IRandomSource();
             IRandomSource();

    // Optional: chooses which RandomAlgorithm GenerateRandomBytes() below uses. Never calling this
    // is valid and means RANDOM_SYSTEM (matches every pre-existing internal caller in this SDK,
    // written before this method existed and unaffected by its addition).
    virtual bool SelectAlgorithm(const RandomAlgorithm algorithm) = 0;

    virtual bool GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

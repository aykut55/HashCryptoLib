#ifndef CRYPTOAPI_PROVIDERS_RANDOM_SOURCE_H
#define CRYPTOAPI_PROVIDERS_RANDOM_SOURCE_H

namespace CryptoApiNS
{

class IRandomSource
{
public:
    virtual ~IRandomSource();
             IRandomSource();

    virtual bool GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

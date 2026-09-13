#ifndef CRYPTOAPI_PROVIDERS_KEY_DERIVATION_H
#define CRYPTOAPI_PROVIDERS_KEY_DERIVATION_H

namespace CryptoApiNS
{

class IKeyDerivation
{
public:
    virtual ~IKeyDerivation();
             IKeyDerivation();

    // password is UTF-8 text; passwordSize counts bytes. derivedKeySize bytes are written to derivedKey.
    virtual bool DerivePasswordKey( const char* password, const unsigned int passwordSize,
                                    const unsigned char* salt, const unsigned int saltSize,
                                    const unsigned int iterationCount,
                                    unsigned char* derivedKey, const unsigned int derivedKeySize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

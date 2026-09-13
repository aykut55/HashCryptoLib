#ifndef CRYPTOAPI_PROVIDERS_BOTAN_PROVIDER_H
#define CRYPTOAPI_PROVIDERS_BOTAN_PROVIDER_H

#include "Providers/AeadCipher.h"
#include "Providers/KeyDerivation.h"
#include "Providers/RandomSource.h"

#include <memory>

namespace CryptoApiNS
{

class CBotanProvider : public IAeadCipher, public IKeyDerivation, public IRandomSource
{
public:
    virtual ~CBotanProvider();
             CBotanProvider();

    // Must be called once before SetKey/Encrypt/Decrypt are used.
    bool Initialize(void);

    virtual unsigned int GetKeySize(void) const;
    virtual unsigned int GetNonceSize(void) const;
    virtual unsigned int GetTagSize(void) const;

    virtual bool SetKey(const unsigned char* key, const unsigned int keySize);

    virtual bool Encrypt( const unsigned char* nonce, const unsigned int nonceSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          unsigned char* outputBuffer,
                          unsigned char* tag, const unsigned int tagSize);

    virtual bool Decrypt( const unsigned char* nonce, const unsigned int nonceSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          const unsigned char* tag, const unsigned int tagSize,
                          unsigned char* outputBuffer);

    virtual bool DerivePasswordKey( const char* password, const unsigned int passwordSize,
                                    const unsigned char* salt, const unsigned int saltSize,
                                    const unsigned int iterationCount,
                                    unsigned char* derivedKey, const unsigned int derivedKeySize);

    virtual bool GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize);

protected:

private:

    // Botan types (AEAD_Mode, etc.) are kept out of this header so callers never need Botan's own
    // headers, include path, or C++20 requirement; only BotanProvider.cpp does.
    struct Impl;
    std::unique_ptr<Impl> impl_;

};

} // namespace CryptoApiNS

#endif

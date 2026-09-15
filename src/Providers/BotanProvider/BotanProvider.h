#ifndef CRYPTOAPI_PROVIDERS_BOTAN_PROVIDER_H
#define CRYPTOAPI_PROVIDERS_BOTAN_PROVIDER_H

#include "Providers/AeadCipher.h"
#include "Providers/AsymmetricCipher.h"
#include "Providers/HashService.h"
#include "Providers/KeyDerivation.h"
#include "Providers/LegacyCipher.h"
#include "Providers/MacService.h"
#include "Providers/RandomSource.h"
#include "Providers/SignatureEngine.h"

#include <memory>

namespace CryptoApiNS
{

class CBotanProvider : public IAeadCipher, public IKeyDerivation, public IRandomSource, public ILegacyCipher, public IAsymmetricCipher, public IMacService, public IHashService, public ISignatureEngine
{
public:
    virtual ~CBotanProvider();
             CBotanProvider();

    // Must be called once before SetKey/Encrypt/Decrypt are used.
    bool Initialize(void);

    // IAeadCipher / ILegacyCipher: overloaded on parameter type, each configures which concrete
    // algorithm this instance implements.
    virtual bool SelectAlgorithm(const AeadAlgorithm algorithm);
    virtual bool SelectAlgorithm(const LegacySymmetricAlgorithm algorithm);

    // Identical signature in both IAeadCipher and ILegacyCipher; one implementation satisfies
    // both and reports/applies to whichever algorithm SelectAlgorithm() most recently configured.
    virtual unsigned int GetKeySize(void) const;
    virtual bool SetKey(const unsigned char* key, const unsigned int keySize);

    // IAeadCipher only
    virtual unsigned int GetNonceSize(void) const;
    virtual unsigned int GetTagSize(void) const;

    virtual bool Encrypt( const unsigned char* nonce, const unsigned int nonceSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          unsigned char* outputBuffer,
                          unsigned char* tag, const unsigned int tagSize);

    virtual bool Decrypt( const unsigned char* nonce, const unsigned int nonceSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          const unsigned char* tag, const unsigned int tagSize,
                          unsigned char* outputBuffer);

    // ILegacyCipher only
    virtual unsigned int GetIvSize(void) const;
    virtual unsigned int GetBlockSize(void) const;

    virtual bool Encrypt( const unsigned char* iv, const unsigned int ivSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                          unsigned int* outputBufferSize);

    virtual bool Decrypt( const unsigned char* iv, const unsigned int ivSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                          unsigned int* outputBufferSize);

    // IKeyDerivation
    virtual bool DerivePasswordKey( const char* password, const unsigned int passwordSize,
                                    const unsigned char* salt, const unsigned int saltSize,
                                    const unsigned int iterationCount,
                                    unsigned char* derivedKey, const unsigned int derivedKeySize);

    // IRandomSource
    virtual bool GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize);

    // IAsymmetricCipher. GenerateKeyPair() is also ISignatureEngine's method (identical signature
    // in both interfaces); it dispatches on an internal flag set by whichever SelectAlgorithm
    // overload (AsymmetricAlgorithm vs SignatureAlgorithm) was called most recently.
    virtual bool SelectAlgorithm(const AsymmetricAlgorithm algorithm);
    virtual bool GenerateKeyPair(void);
    virtual unsigned int GetMaxPlaintextSize(void) const;
    virtual unsigned int GetCiphertextSize(void) const;

    virtual bool Encrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                        unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                        unsigned int* outputBufferSize);

    virtual bool Decrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                        unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                        unsigned int* outputBufferSize);

    // IMacService
    virtual unsigned int GetMacSize(void) const;

    virtual bool ComputeMac( const unsigned char* key, const unsigned int keySize,
                            const unsigned char* data, const unsigned int dataSize,
                            unsigned char* mac, const unsigned int macSize);

    // IHashService
    virtual bool SelectAlgorithm(const HashAlgorithm algorithm);
    virtual unsigned int GetHashSize(void) const;

    virtual bool ComputeHash( const unsigned char* data, const unsigned int dataSize,
                             unsigned char* hash, const unsigned int hashSize);

    virtual bool Init(void);
    virtual bool Update(const unsigned char* data, const unsigned int dataSize);
    virtual bool Final(unsigned char* hash, const unsigned int hashSize);

    // ISignatureEngine (GenerateKeyPair declared above, shared with IAsymmetricCipher)
    virtual bool SelectAlgorithm(const SignatureAlgorithm algorithm);
    virtual unsigned int GetSignatureSize(void) const;

    virtual bool Sign( const unsigned char* data, const unsigned int dataSize,
                      unsigned char* signature, const unsigned int signatureSize);

    virtual bool Verify( const unsigned char* data, const unsigned int dataSize,
                        const unsigned char* signature, const unsigned int signatureSize);

protected:

private:

    // Botan types (AEAD_Mode, Cipher_Mode, etc.) are kept out of this header so callers never
    // need Botan's own headers, include path, or C++20 requirement; only BotanProvider.cpp does.
    struct Impl;
    std::unique_ptr<Impl> impl_;

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_PROVIDERS_MICROSOFT_PROVIDER_H
#define CRYPTOAPI_PROVIDERS_MICROSOFT_PROVIDER_H

#include "Providers/AeadCipher.h"
#include "Providers/AsymmetricCipher.h"
#include "Providers/KeyDerivation.h"
#include "Providers/LegacyCipher.h"
#include "Providers/MacService.h"
#include "Providers/RandomSource.h"

#include <vector>

namespace CryptoApiNS
{

class CMicrosoftProvider : public IAeadCipher, public IKeyDerivation, public IRandomSource, public ILegacyCipher, public IAsymmetricCipher, public IMacService
{
public:
    virtual ~CMicrosoftProvider();
             CMicrosoftProvider();

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

    // IAsymmetricCipher
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

protected:

private:

    // BCRYPT_ALG_HANDLE/BCRYPT_KEY_HANDLE are themselves just typedef'd void*, so storing them as
    // void* here does not require <bcrypt.h> in this header; only MicrosoftProvider.cpp needs it.
    void* algorithmHandle_;
    void* keyHandle_;
    unsigned long keyObjectSize_;
    std::vector<unsigned char> keyObject_;

    bool legacySelected_;
    bool isPadded_;
    unsigned int keySize_;
    unsigned int ivOrNonceSize_;
    unsigned int tagSize_;
    unsigned int blockSize_;

    // Separate handles for the RSA (asymmetric) key pair; unrelated to the symmetric
    // algorithmHandle_/keyHandle_ above, which are never both in use for the same instance.
    void* rsaAlgorithmHandle_;
    void* rsaKeyHandle_;
    unsigned int rsaKeyBits_;

};

} // namespace CryptoApiNS

#endif

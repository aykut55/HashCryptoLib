#ifndef CRYPTOAPI_PROVIDERS_ASYMMETRIC_CIPHER_H
#define CRYPTOAPI_PROVIDERS_ASYMMETRIC_CIPHER_H

#include "Providers/ProviderTypes.h"

namespace CryptoApiNS
{

// Public/private key-pair cipher (currently RSA only). Unlike IAeadCipher/ILegacyCipher there is
// no SetKey(): GenerateKeyPair() creates a fresh key pair sized per the algorithm selected via
// SelectAlgorithm(). Encrypt() uses this instance's own public key, Decrypt() uses its own private
// key -- there is no export/import of key material yet, so this models a self-contained round
// trip (e.g. protecting a symmetric key at rest) rather than a two-party exchange.
class IAsymmetricCipher
{
public:
    virtual ~IAsymmetricCipher();
             IAsymmetricCipher();

    // Must be called once, before GenerateKeyPair, to configure which key size this instance uses.
    virtual bool SelectAlgorithm(const AsymmetricAlgorithm algorithm) = 0;

    // Generates a fresh key pair for the selected algorithm. Must be called once before
    // Encrypt/Decrypt/GetMaxPlaintextSize/GetCiphertextSize are used.
    virtual bool GenerateKeyPair(void) = 0;

    // Largest plaintext Encrypt() can accept in one call; depends on key size and padding scheme.
    virtual unsigned int GetMaxPlaintextSize(void) const = 0;

    // Exact ciphertext size Encrypt() produces (fixed: equal to the RSA modulus size in bytes).
    virtual unsigned int GetCiphertextSize(void) const = 0;

    virtual bool Encrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                        unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                        unsigned int* outputBufferSize) = 0;

    virtual bool Decrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                        unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                        unsigned int* outputBufferSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

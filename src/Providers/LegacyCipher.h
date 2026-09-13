#ifndef CRYPTOAPI_PROVIDERS_LEGACY_CIPHER_H
#define CRYPTOAPI_PROVIDERS_LEGACY_CIPHER_H

#include "Providers/ProviderTypes.h"

namespace CryptoApiNS
{

// Plain (non-authenticated) symmetric cipher: no built-in integrity tag. See
// LegacySymmetricAlgorithm in ProviderTypes.h for why this exists only as an explicit
// legacy-interop path, never a default encryption choice.
class ILegacyCipher
{
public:
    virtual ~ILegacyCipher();
             ILegacyCipher();

    // Must be called once, before GetKeySize/GetIvSize/GetBlockSize/SetKey, to configure which
    // algorithm this instance implements.
    virtual bool SelectAlgorithm(const LegacySymmetricAlgorithm algorithm) = 0;

    virtual unsigned int GetKeySize(void) const = 0;
    // 0 for algorithms that use no IV (ECB).
    virtual unsigned int GetIvSize(void) const = 0;
    // Block size in bytes. Block modes (CBC/ECB) pad the plaintext up to this boundary, so their
    // ciphertext can be up to one block larger than the plaintext. Stream-like modes (CTR/CFB/OFB)
    // report the underlying cipher's block size but do not pad; their ciphertext length equals the
    // plaintext length.
    virtual unsigned int GetBlockSize(void) const = 0;

    virtual bool SetKey(const unsigned char* key, const unsigned int keySize) = 0;

    // outputBufferCapacity == 0 (and outputBuffer == nullptr) queries the required capacity:
    // outputBufferSize is set to that requirement and the call returns false without encrypting.
    virtual bool Encrypt( const unsigned char* iv, const unsigned int ivSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                          unsigned int* outputBufferSize) = 0;

    virtual bool Decrypt( const unsigned char* iv, const unsigned int ivSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                          unsigned int* outputBufferSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

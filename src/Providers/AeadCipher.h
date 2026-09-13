#ifndef CRYPTOAPI_PROVIDERS_AEAD_CIPHER_H
#define CRYPTOAPI_PROVIDERS_AEAD_CIPHER_H

#include "Providers/ProviderTypes.h"
#include "Providers/RandomSource.h"

namespace CryptoApiNS
{

// Invoked after each chunk during EncryptChunked/DecryptChunked. processedBytes/totalBytes are
// measured in bytes of the plaintext stream; percentage is processedBytes/totalBytes * 100.
// Return true to continue, or false to abort at the next chunk boundary (the call then fails).
typedef bool (__cdecl *AeadProgressCallback)( const unsigned long long processedBytes,
                                              const unsigned long long totalBytes,
                                              const double percentage,
                                              void* userData);

class IAeadCipher
{
public:
    virtual ~IAeadCipher();
             IAeadCipher();

    // Must be called once, before GetKeySize/GetNonceSize/GetTagSize/SetKey, to configure which
    // algorithm this instance implements. GetKeySize/GetNonceSize/GetTagSize return values that
    // depend on the selected algorithm (e.g. AES-128 vs AES-256 key size, GCM vs CCM tag size).
    virtual bool SelectAlgorithm(const AeadAlgorithm algorithm) = 0;

    virtual unsigned int GetKeySize(void) const = 0;
    virtual unsigned int GetNonceSize(void) const = 0;
    virtual unsigned int GetTagSize(void) const = 0;

    virtual bool SetKey(const unsigned char* key, const unsigned int keySize) = 0;

    virtual bool Encrypt( const unsigned char* nonce, const unsigned int nonceSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          unsigned char* outputBuffer,
                          unsigned char* tag, const unsigned int tagSize) = 0;

    virtual bool Decrypt( const unsigned char* nonce, const unsigned int nonceSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          const unsigned char* tag, const unsigned int tagSize,
                          unsigned char* outputBuffer) = 0;

    // Chunked/streaming AEAD over an in-memory buffer: splits inputBuffer into chunkSize-sized
    // pieces, encrypts each with a freshly-generated nonce (via randomSource -- a fresh nonce per
    // chunk is mandatory for AEAD safety when the same key is reused across chunks), and writes
    // each as a self-delimited record into outputBuffer, one after another:
    //   [4-byte little-endian plaintext chunk length][nonce][ciphertext][tag]
    // Same capacity-query convention as ILegacyCipher: pass outputBuffer=nullptr and/or
    // outputBufferCapacity=0 first to learn the required size via *outputBufferSize.
    // Implemented once here in terms of GetNonceSize/GetTagSize/Encrypt, so no provider needs to
    // override it; kept virtual only in case a future provider gains a true incremental AEAD API.
    virtual bool EncryptChunked( IRandomSource& randomSource,
                                const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                                const unsigned int chunkSize,
                                unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                                unsigned int* outputBufferSize,
                                AeadProgressCallback onProgress, void* progressUserData);

    // Inverse of EncryptChunked: reads consecutive [length][nonce][ciphertext][tag] records from
    // inputBuffer until fully consumed, decrypting each into outputBuffer. The algorithm selected
    // via SelectAlgorithm must match the one used to encrypt (GetNonceSize/GetTagSize must agree).
    virtual bool DecryptChunked( const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                                unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                                unsigned int* outputBufferSize,
                                AeadProgressCallback onProgress, void* progressUserData);

protected:

private:

};

} // namespace CryptoApiNS

#endif

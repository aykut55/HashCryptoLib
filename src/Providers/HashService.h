#ifndef CRYPTOAPI_PROVIDERS_HASH_SERVICE_H
#define CRYPTOAPI_PROVIDERS_HASH_SERVICE_H

#include "Providers/ProviderTypes.h"

namespace CryptoApiNS
{

// Cryptographic hash (message digest) computation, one algorithm per instance. Mirrors
// ILegacyCipher/IAeadCipher's SelectAlgorithm shape (not IMacService's fixed-algorithm shape,
// since callers do need to choose among HASH_MD5/HASH_SHA256/etc). Offers both a one-shot
// ComputeHash for small in-memory buffers and an incremental Init/Update/Final trio for streaming
// large inputs (e.g. a future CCryptoApi::ComputeHashFile reading a file chunk by chunk) without
// holding the whole input in memory at once.
class IHashService
{
public:
    virtual ~IHashService();
             IHashService();

    // Must be called once, before GetHashSize/ComputeHash/Init, to configure which algorithm this
    // instance implements.
    virtual bool SelectAlgorithm(const HashAlgorithm algorithm) = 0;

    // Output size of ComputeHash/Final in bytes for the selected algorithm.
    virtual unsigned int GetHashSize(void) const = 0;

    // One-shot digest of a single in-memory buffer. Equivalent to Init() + Update(data, dataSize)
    // + Final(hash, hashSize), provided separately for the common case where the whole input is
    // already in memory.
    virtual bool ComputeHash( const unsigned char* data, const unsigned int dataSize,
                              unsigned char* hash, const unsigned int hashSize) = 0;

    // Resets this instance to start a new incremental digest. Must be called before the first
    // Update()/Final() of each digest (ComputeHash calls it internally, so mixing ComputeHash and
    // Init/Update/Final calls on the same instance is safe as long as each digest starts with
    // either a fresh ComputeHash call or a fresh Init() call).
    virtual bool Init(void) = 0;

    // Feeds more input bytes into the digest in progress. May be called any number of times after
    // Init() and before Final().
    virtual bool Update(const unsigned char* data, const unsigned int dataSize) = 0;

    // Finalizes the digest in progress and writes it to hash (hashSize must be >= GetHashSize()).
    // After this call, Init() must be called again before the next Update().
    virtual bool Final(unsigned char* hash, const unsigned int hashSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_PROVIDERS_MAC_SERVICE_H
#define CRYPTOAPI_PROVIDERS_MAC_SERVICE_H

namespace CryptoApiNS
{

// HMAC-SHA256 message authentication. Algorithm-fixed (no SelectAlgorithm) like IRandomSource/
// IKeyDerivation: every provider implements exactly HMAC-SHA256 here, so callers never need to
// query which algorithm this instance uses. Used to add Encrypt-then-MAC integrity on top of
// ILegacyCipher, which has no built-in authentication tag of its own.
class IMacService
{
public:
    virtual ~IMacService();
             IMacService();

    // Fixed output size of ComputeMac/VerifyMac in bytes (HMAC-SHA256 = 32).
    virtual unsigned int GetMacSize(void) const = 0;

    virtual bool ComputeMac( const unsigned char* key, const unsigned int keySize,
                             const unsigned char* data, const unsigned int dataSize,
                             unsigned char* mac, const unsigned int macSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

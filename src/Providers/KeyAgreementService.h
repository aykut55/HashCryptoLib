#ifndef CRYPTOAPI_PROVIDERS_KEY_AGREEMENT_SERVICE_H
#define CRYPTOAPI_PROVIDERS_KEY_AGREEMENT_SERVICE_H

#include "Providers/ProviderTypes.h"

namespace CryptoApiNS
{

// Key agreement (Diffie-Hellman style: two parties each generate a key pair, exchange public keys,
// and independently derive the same shared secret), one algorithm per instance. Unlike
// IAsymmetricCipher/ISignatureEngine -- both modeled as a self-contained round trip inside one
// instance -- key agreement is inherently a two-party protocol: GetPublicKey() exports this
// instance's own public key to hand to a second, independently created instance (the peer), and
// DeriveSharedSecret() combines this instance's private key with that peer's exported public key.
// Two instances of the SAME provider (same ProviderKind) are expected to derive an identical shared
// secret; the raw public key wire format is each provider's own internal encoding, not a
// cross-provider standard, so a public key exported by one ProviderKind must not be fed to a
// DeriveSharedSecret() call on a different ProviderKind (mirrors ISignatureEngine's own
// self-contained-round-trip limitation -- see future_signing_key_agreement memory).
class IKeyAgreementService
{
public:
    virtual ~IKeyAgreementService();
             IKeyAgreementService();

    // Must be called once, before GenerateKeyPair/GetPublicKeySize/GetSharedSecretSize/
    // GetPublicKey/DeriveSharedSecret, to configure which algorithm this instance implements.
    virtual bool SelectAlgorithm(const KeyAgreementAlgorithm algorithm) = 0;

    // Generates a fresh key pair for the selected algorithm; the private key never leaves this
    // instance. Must be called once before GetPublicKey()/DeriveSharedSecret(). Calling it again
    // rotates to a fresh key pair; a new DeriveSharedSecret() call then uses the new key pair.
    virtual bool GenerateKeyPair(void) = 0;

    // Exact public key size in bytes for the selected algorithm; 0 before a key pair exists.
    virtual unsigned int GetPublicKeySize(void) const = 0;

    // Exact shared secret size in bytes for the selected algorithm; 0 before a key pair exists.
    virtual unsigned int GetSharedSecretSize(void) const = 0;

    // Exports this instance's own public key (GetPublicKeySize() bytes), to be handed to the peer
    // instance's DeriveSharedSecret() call.
    virtual bool GetPublicKey(unsigned char* publicKey, const unsigned int publicKeySize) const = 0;

    // Combines this instance's private key with a peer instance's public key (as produced by that
    // peer's own GetPublicKey(), same algorithm, same ProviderKind) to compute the shared secret.
    // Both sides of a valid exchange produce byte-identical output.
    virtual bool DeriveSharedSecret( const unsigned char* peerPublicKey, const unsigned int peerPublicKeySize,
                                    unsigned char* sharedSecret, const unsigned int sharedSecretSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_PROVIDERS_SIGNATURE_ENGINE_H
#define CRYPTOAPI_PROVIDERS_SIGNATURE_ENGINE_H

#include "Providers/ProviderTypes.h"

namespace CryptoApiNS
{

// Digital signature (sign/verify with a public/private key pair), one algorithm per instance.
// Mirrors IAsymmetricCipher's shape (SelectAlgorithm + GenerateKeyPair + a fixed-size-output
// query + the actual operations) since both are public/private key-pair primitives with no
// caller-supplied key. Named ISignatureEngine per Plan.md section 6.1's own interface list.
class ISignatureEngine
{
public:
    virtual ~ISignatureEngine();
             ISignatureEngine();

    // Must be called once, before GenerateKeyPair/GetSignatureSize/Sign/Verify, to configure
    // which algorithm this instance implements.
    virtual bool SelectAlgorithm(const SignatureAlgorithm algorithm) = 0;

    // Generates a fresh key pair for the selected algorithm; the private key never leaves this
    // instance. Must be called once before Sign(); Verify() also needs a key pair (this SDK does
    // not yet support importing a public key to verify third-party signatures -- see
    // future_signing_key_agreement). Calling it again rotates to a fresh key pair (old signatures
    // become unverifiable against this instance).
    virtual bool GenerateKeyPair(void) = 0;

    // Exact signature size in bytes for the selected algorithm (and, for RSA, the generated key's
    // modulus size); 0 before a key pair exists.
    virtual unsigned int GetSignatureSize(void) const = 0;

    // Signs data with the private key. signatureSize must be >= GetSignatureSize(); the signature
    // is always written at exactly GetSignatureSize() bytes (fixed per algorithm, see
    // SignatureAlgorithm's doc comment on ECDSA's raw r||s format).
    virtual bool Sign( const unsigned char* data, const unsigned int dataSize,
                       unsigned char* signature, const unsigned int signatureSize) = 0;

    // Verifies a signature against data with the public key. Returns true only if the signature
    // is cryptographically valid for this exact data and this instance's key pair; any mismatch,
    // corruption, or wrong-size signature returns false (no separate "indeterminate" state --
    // SelectAlgorithm/CreateSignatureEngine already gate unsupported algorithms before this point).
    virtual bool Verify( const unsigned char* data, const unsigned int dataSize,
                        const unsigned char* signature, const unsigned int signatureSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

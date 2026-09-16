#ifndef CRYPTOAPI_PROVIDERS_MICROSOFT_PROVIDER_H
#define CRYPTOAPI_PROVIDERS_MICROSOFT_PROVIDER_H

#include "Providers/AeadCipher.h"
#include "Providers/AsymmetricCipher.h"
#include "Providers/HashService.h"
#include "Providers/KeyAgreementService.h"
#include "Providers/KeyDerivation.h"
#include "Providers/LegacyCipher.h"
#include "Providers/MacService.h"
#include "Providers/RandomSource.h"
#include "Providers/SignatureEngine.h"

#include <vector>

namespace CryptoApiNS
{

class CMicrosoftProvider : public IAeadCipher, public IKeyDerivation, public IRandomSource, public ILegacyCipher, public IAsymmetricCipher, public IMacService, public IHashService, public ISignatureEngine, public IKeyAgreementService
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

    // IRandomSource. Only RANDOM_SYSTEM is supported -- CNG's system-preferred RNG is internally
    // CTR_DRBG-based, but that is not separately selectable through any stable public CNG API, so
    // RANDOM_HASH_DRBG/HMAC_DRBG/CTR_DRBG all correctly report unsupported here.
    virtual bool SelectAlgorithm(const RandomAlgorithm algorithm);
    virtual bool GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize);

    // IAsymmetricCipher. GenerateKeyPair() is also ISignatureEngine's method (identical signature
    // in both interfaces, like GetKeySize/SetKey are shared between IAeadCipher/ILegacyCipher
    // above) -- it dispatches on asymmetricModeIsSignature_, set by whichever SelectAlgorithm
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

    // IKeyAgreementService (GenerateKeyPair declared above, shared with IAsymmetricCipher/
    // ISignatureEngine -- dispatches on asymmetricModeIsKeyAgreement_, see its declaration below).
    virtual bool SelectAlgorithm(const KeyAgreementAlgorithm algorithm);
    virtual unsigned int GetPublicKeySize(void) const;
    virtual unsigned int GetSharedSecretSize(void) const;

    virtual bool GetPublicKey(unsigned char* publicKey, const unsigned int publicKeySize) const;

    virtual bool DeriveSharedSecret( const unsigned char* peerPublicKey, const unsigned int peerPublicKeySize,
                                    unsigned char* sharedSecret, const unsigned int sharedSecretSize);

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

    // ISignatureEngine state -- separate key material from rsaAlgorithmHandle_/rsaKeyHandle_
    // above (that pair is RSA-OAEP encryption; this is RSA-PSS/ECDSA/Ed25519 signing, a distinct
    // key even when both happen to be RSA). asymmetricModeIsSignature_ is the dispatch flag
    // GenerateKeyPair() reads to decide which key pair to generate (see the comment on its
    // declaration above).
    bool asymmetricModeIsSignature_;
    SignatureAlgorithm signatureAlgorithm_;
    void* signatureAlgorithmHandle_;
    void* signatureKeyHandle_;
    unsigned int signatureSize_;

    // IHashService state -- separate from algorithmHandle_/keyHandle_ above (unrelated, never both
    // in use for the same instance). hashObjectBuffer_ backs the CNG hash object for the
    // incremental BCryptCreateHash/BCryptHashData/BCryptFinishHash API, sized per
    // BCRYPT_OBJECT_LENGTH like keyObject_ is for symmetric ciphers.
    void* hashAlgorithmHandle_;
    void* hashObjectHandle_;
    std::vector<unsigned char> hashObjectBuffer_;
    unsigned int hashOutputSize_;

    // IKeyAgreementService state -- separate key material from rsaAlgorithmHandle_/rsaKeyHandle_
    // and signatureAlgorithmHandle_/signatureKeyHandle_ above (all three are distinct key pairs,
    // never in use simultaneously for the same instance). asymmetricModeIsKeyAgreement_ is the
    // dispatch flag GenerateKeyPair() checks first (before asymmetricModeIsSignature_) to decide
    // which key pair to generate -- see the comment on GenerateKeyPair's declaration above.
    bool asymmetricModeIsKeyAgreement_;
    KeyAgreementAlgorithm keyAgreementAlgorithm_;
    void* keyAgreementAlgorithmHandle_;
    void* keyAgreementKeyHandle_;
    unsigned int keyAgreementPublicKeySize_;
    unsigned int keyAgreementSharedSecretSize_;

};

} // namespace CryptoApiNS

#endif

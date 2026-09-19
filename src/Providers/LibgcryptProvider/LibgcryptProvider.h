#ifndef CRYPTOAPI_PROVIDERS_LIBGCRYPT_PROVIDER_H
#define CRYPTOAPI_PROVIDERS_LIBGCRYPT_PROVIDER_H

#include "Providers/AeadCipher.h"
#include "Providers/AsymmetricCipher.h"
#include "Providers/HashService.h"
#include "Providers/KeyAgreementService.h"
#include "Providers/KeyDerivation.h"
#include "Providers/LegacyCipher.h"
#include "Providers/MacService.h"
#include "Providers/RandomSource.h"
#include "Providers/SignatureEngine.h"

#include <memory>

namespace CryptoApiNS
{

// libgcrypt (GnuPG's crypto library) backed provider, the 5th ICryptoProvider implementation
// alongside CMicrosoftProvider/CCryptoPPProvider/CBotanProvider/COpenSslProvider. Same class shape
// as those four: one class implementing every provider interface, with all library-specific state
// hidden in a pimpl so callers never need gcrypt.h or its include path.
//
// IMPORTANT -- x64 only. The vendored libgcrypt bundle
// (3rdParty/libgcryptbundle11241, libgcrypt 1.12.4 + libgpg-error) ships an x64 DLL and an x64
// MSVC import library only; no Win32/x86 build exists. Under a Win32 configuration (ARCH_WIN32/
// ARCH_X86, see Rules.md) this class still compiles and links, but no libgcrypt call is compiled in
// at all and every capability query / operation reports "unsupported" (returns false, or 0 for the
// size queries) -- the same honest-unsupported convention CMicrosoftProvider already uses for
// SIGNATURE_ED25519/KEYAGREEMENT_X25519, never silently wrong output.
class CLibgcryptProvider : public IAeadCipher, public IKeyDerivation, public IRandomSource, public ILegacyCipher, public IAsymmetricCipher, public IMacService, public IHashService, public ISignatureEngine, public IKeyAgreementService
{
public:
    virtual ~CLibgcryptProvider();
             CLibgcryptProvider();

    // Must be called once before SetKey/Encrypt/Decrypt are used. Also performs libgcrypt's
    // one-time process-wide initialization (gcry_check_version + GCRYCTL_INITIALIZATION_FINISHED),
    // which libgcrypt requires before any other gcry_* call; returns false on Win32 (see the class
    // comment) and whenever that initialization fails.
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
    virtual bool SelectAlgorithm(const RandomAlgorithm algorithm);
    virtual bool GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize);

    // IAsymmetricCipher. GenerateKeyPair() is also ISignatureEngine's and IKeyAgreementService's
    // method (identical signature in all three); it dispatches on internal flags set by whichever
    // SelectAlgorithm overload (AsymmetricAlgorithm vs SignatureAlgorithm vs KeyAgreementAlgorithm)
    // was called most recently.
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
    // ISignatureEngine -- dispatches on impl_->asymmetricModeIsKeyAgreement, see Impl in the .cpp).
    virtual bool SelectAlgorithm(const KeyAgreementAlgorithm algorithm);
    virtual unsigned int GetPublicKeySize(void) const;
    virtual unsigned int GetSharedSecretSize(void) const;

    virtual bool GetPublicKey(unsigned char* publicKey, const unsigned int publicKeySize) const;

    virtual bool DeriveSharedSecret( const unsigned char* peerPublicKey, const unsigned int peerPublicKeySize,
                                    unsigned char* sharedSecret, const unsigned int sharedSecretSize);

protected:

private:

    // libgcrypt types are kept out of this header so callers never need gcrypt.h or its include
    // path; only LibgcryptProvider.cpp does. On Win32 (no libgcrypt binary, see the class comment)
    // Impl is an empty placeholder so this class still has the exact same ABI shape.
    struct Impl;
    std::unique_ptr<Impl> impl_;

};

} // namespace CryptoApiNS

#endif

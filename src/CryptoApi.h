#ifndef AYCRYPTO_CRYPTO_API_H
#define AYCRYPTO_CRYPTO_API_H

#define CRYPTOAPI_VERSION_MAJOR 0
#define CRYPTOAPI_VERSION_MINOR 1
#define CRYPTOAPI_VERSION_BUILD_NUMBER 0
#define CRYPTOAPI_BUILD_DATE_RAW __DATE__
#define CRYPTOAPI_BUILD_TIME __TIME__

#include "Definitions/Definitions.h"
#include "Providers/ProviderTypes.h"

#include <memory>

namespace CryptoApiNS
{

class IAsymmetricCipher;
class ISignatureEngine;
class IKeyAgreementService;

// Cache key uniquely identifying a CCryptoApi configuration -- the resolved value of all 7
// algorithm-selecting fields a constructor can set (directly or via its own defaults), used by
// CCryptoApi::GetShared() below. Two constructor calls that end up with the same 7-tuple (even via
// different constructor overloads) are considered the same configuration.
struct CCryptoApiConfig
{
    ProviderKind providerKind;
    AeadAlgorithm aeadAlgorithm;
    AsymmetricAlgorithm asymmetricAlgorithm;
    LegacySymmetricAlgorithm legacyAlgorithm;
    HashAlgorithm hashAlgorithm;
    SignatureAlgorithm signatureAlgorithm;
    KeyAgreementAlgorithm keyAgreementAlgorithm;

    // Strict weak ordering over all 7 fields, needed only so CCryptoApiConfig can be a std::map key
    // (see GetShared's implementation) -- the ordering itself has no other meaning.
    bool operator<(const CCryptoApiConfig& other) const;
};

class CCryptoApi
{
public:
    virtual ~CCryptoApi();
             CCryptoApi();

    // AEAD-only: for callers who only need EncryptBuffer/DecryptBuffer/EncryptBytes/DecryptBytes/
    // EncryptString/DecryptString/EncryptFile/DecryptFile -- the original, most common case this
    // class was built for. The single-purpose constructors below (Hash-only/Asymmetric-only/
    // Legacy-only) follow this same pattern for their own primitive.
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm);

    // Hash-only: for callers who only need ComputeHashBuffer/ComputeHashBytes/ComputeHashString/
    // ComputeHashFile and never touch Encrypt*/Decrypt*/RSA/Legacy at all. aeadAlgorithm_/
    // asymmetricAlgorithm_/legacyAlgorithm_ still get sane defaults (see CryptoApi.cpp) so every
    // other method stays well-defined if called anyway, but this constructor's whole point is that
    // a hash-only caller never needs to think about them. Distinguishable from the 2-argument AEAD
    // constructor above by the 2nd parameter's type (HashAlgorithm vs AeadAlgorithm are distinct
    // enum types, so there is no overload ambiguity).
             CCryptoApi(const ProviderKind providerKind, const HashAlgorithm hashAlgorithm);

    // Asymmetric-only: for callers who only need GenerateAsymmetricKeyPair/EncryptWithPublicKey/
    // DecryptWithPrivateKey/GetMaxAsymmetricPlaintextSize/GetAsymmetricCiphertextSize. Same
    // reasoning as the Hash-only constructor above -- RSA never touches AEAD, so a caller
    // shouldn't have to pick an AeadAlgorithm just to use it. No overload ambiguity: AsymmetricAlgorithm
    // is a distinct enum type from AeadAlgorithm/HashAlgorithm.
             CCryptoApi(const ProviderKind providerKind, const AsymmetricAlgorithm asymmetricAlgorithm);

    // Legacy-only: for callers who only need EncryptLegacyBuffer/DecryptLegacyBuffer. Same
    // reasoning again -- Legacy+MAC never touches AEAD either.
             CCryptoApi(const ProviderKind providerKind, const LegacySymmetricAlgorithm legacyAlgorithm);

    // Signature-only: for callers who only need GenerateSignatureKeyPair/SignBuffer/VerifyBuffer/
    // GetSignatureSize. Same reasoning again -- signing never touches AEAD either.
             CCryptoApi(const ProviderKind providerKind, const SignatureAlgorithm signatureAlgorithm);

    // Key-agreement-only: for callers who only need GenerateKeyAgreementKeyPair/
    // GetKeyAgreementPublicKeySize/GetSharedSecretSize/ExportKeyAgreementPublicKey/
    // DeriveSharedSecret. Same reasoning again -- key agreement never touches AEAD either.
             CCryptoApi(const ProviderKind providerKind, const KeyAgreementAlgorithm keyAgreementAlgorithm);

             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm);
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm);
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm);
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm);
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm, const KeyAgreementAlgorithm keyAgreementAlgorithm);

    // ============================================================================================
    // Shared/cached instances -- deliberately NOT a classic global Singleton (Plan.md section 4
    // rules that out by design: multiple independently-configured CCryptoApi instances must be able
    // to coexist in the same process). This is a per-CONFIGURATION cache instead (sometimes called
    // a Multiton): GetShared() called twice with the SAME arguments returns a reference to the SAME
    // instance; called with DIFFERENT arguments (even via a different overload -- see
    // CCryptoApiConfig above) it returns a DIFFERENT instance. Every constructor above is completely
    // unaffected and keeps creating a fresh, independent, uncached instance -- GetShared() is a
    // purely additive convenience for callers who want to avoid re-constructing (and, once a key
    // pair has been generated on it, re-generating) "the same" configuration repeatedly.
    //
    // SECURITY-RELEVANT: the returned CCryptoApi& is SHARED STATE. If one caller calls
    // GenerateSignatureKeyPair()/GenerateAsymmetricKeyPair()/GenerateKeyAgreementKeyPair() on it,
    // every OTHER caller requesting the same configuration observes the SAME key pair, not a fresh
    // one -- that sharing is the entire point (avoiding redundant, expensive key generation), but it
    // means GetShared() is only appropriate when callers genuinely intend to share one key/config
    // app-wide (e.g. "the process's one default signing key"). When independent, unrelated key
    // pairs are required, use a plain constructor (above) instead -- never GetShared().
    //
    // THREAD-SAFETY: lookup/creation in the shared cache is mutex-protected, so calling GetShared()
    // concurrently from multiple threads (for any mix of arguments) is safe by itself. The returned
    // CCryptoApi instance's OWN methods are NOT independently made thread-safe by this cache --
    // concurrent calls into the same shared instance (e.g. one thread's GenerateSignatureKeyPair()
    // racing another thread's SignBuffer()) are the caller's own responsibility to serialize, same
    // as for any object shared across threads.
    // ============================================================================================

    static CCryptoApi& GetShared(void);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const HashAlgorithm hashAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const AsymmetricAlgorithm asymmetricAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const LegacySymmetricAlgorithm legacyAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const SignatureAlgorithm signatureAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const KeyAgreementAlgorithm keyAgreementAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm);
    static CCryptoApi& GetShared(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm, const KeyAgreementAlgorithm keyAgreementAlgorithm);

    // Destroys every cached shared instance (their destructors run, releasing any generated key
    // material). Any reference previously returned by GetShared() becomes dangling immediately --
    // callers must not keep using a GetShared() reference across a ResetShared() call. Intended for
    // test teardown/process shutdown, not a normal-operation API.
    static void ResetShared(void);

    // ============================================================================================
    // DO NOT USE THIS. Kept only for callers/checklists that specifically expect a classic
    // Instance()-style global singleton accessor to exist; it is intentionally the LEAST flexible
    // option in this file and contradicts Plan.md section 4's explicit design decision ("Global
    // Singleton kullanılmayacak" -- no global singleton, because multiple independently-configured
    // CCryptoApi instances must be able to coexist in the same process). Unlike GetShared() above
    // (a per-CONFIGURATION cache -- many independent shared instances, one per distinct argument
    // combination), Instance() collapses the ENTIRE PROCESS onto exactly one fixed configuration
    // (the no-argument constructor's defaults: PROVIDER_MICROSOFT / AEAD_AES_256_GCM /
    // ASYMMETRIC_RSA_2048 / LEGACY_AES_256_CBC / HASH_SHA256 / SIGNATURE_ECDSA_P256_SHA256 /
    // KEYAGREEMENT_ECDH_P256) -- there is no way to ever get a second one, no way to pick a
    // different provider or algorithm anywhere in the process, and every one of this class's other
    // constructors becomes effectively unreachable for any code that starts depending on this
    // accessor. Prefer a plain constructor for an independent instance, or GetShared() for a shared
    // instance that still lets different call sites choose different configurations.
    // ============================================================================================

    static CCryptoApi& Instance(void);

    const char* GetVersion(void) const;

    // Buffers contain raw bytes; password is UTF-8 and passwordSize counts bytes. Input is
    // processed in chunks so large buffers report progress; onProgress may be nullptr.
    int EncryptBuffer( const char* password, const int passwordSize,
                       const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputBufferCapacity,
                       unsigned char* outputBuffer,
                       int* outputBufferSize,
                       ProgressCallback onProgress,
                       void* progressUserData);

    // Buffers contain raw bytes; password is UTF-8 and passwordSize counts bytes. Input is
    // processed in chunks so large buffers report progress; onProgress may be nullptr.
    int DecryptBuffer( const char* password, const int passwordSize,
                       const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputBufferCapacity,
                       unsigned char* outputBuffer,
                       int* outputBufferSize,
                       ProgressCallback onProgress,
                       void* progressUserData);

    // Alias of EncryptBuffer with an identical chunked implementation and format.
    int EncryptBytes( const char* password, const int passwordSize,
                      const unsigned char* inputBuffer, const int inputBufferSize,
                      const int outputBufferCapacity,
                      unsigned char* outputBuffer,
                      int* outputBufferSize,
                      ProgressCallback onProgress,
                      void* progressUserData);

    // Alias of DecryptBuffer with an identical chunked implementation and format.
    int DecryptBytes( const char* password, const int passwordSize,
                      const unsigned char* inputBuffer, const int inputBufferSize,
                      const int outputBufferCapacity,
                      unsigned char* outputBuffer,
                      int* outputBufferSize,
                      ProgressCallback onProgress,
                      void* progressUserData);

    // String input and output use UTF-8 bytes; output is caller-owned and sized in bytes.
    // Input is processed in chunks so large strings report progress; onProgress may be nullptr.
    int EncryptString( const char* password, const int passwordSize,
                       const char* inputString, const int inputStringSize,
                       const int outputBufferCapacity,
                       unsigned char* outputBuffer,
                       int* outputBufferSize,
                       ProgressCallback onProgress,
                       void* progressUserData);

    // Decrypted UTF-8 bytes are written to the caller-owned char buffer; no terminator is appended.
    // Input is processed in chunks so large strings report progress; onProgress may be nullptr.
    int DecryptString( const char* password, const int passwordSize,
                       const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputStringBufferCapacity,
                       char* outputStringBuffer,
                       int* outputStringSize,
                       ProgressCallback onProgress,
                       void* progressUserData);

    // Password and file paths are UTF-8 strings. onProgress may be nullptr; when provided it is
    // invoked after each processed chunk with cumulative bytes and percentage complete.
    int EncryptFile( const char* password,
                     const char* inputFilePath,
                     const char* outputFilePath,
                     ProgressCallback onProgress,
                     void* progressUserData);

    int DecryptFile( const char* password,
                     const char* inputFilePath,
                     const char* outputFilePath,
                     ProgressCallback onProgress,
                     void* progressUserData);

    // RSA (self-contained round trip): generates a fresh key pair for this instance's
    // asymmetricAlgorithm (see the 3-argument constructor); the private key never leaves this
    // instance. Must be called once before EncryptWithPublicKey/DecryptWithPrivateKey/
    // GetMaxAsymmetricPlaintextSize/GetAsymmetricCiphertextSize; calling it again rotates to a
    // fresh key pair (old ciphertexts become undecryptable).
    int GenerateAsymmetricKeyPair(void);

    // Largest plaintext EncryptWithPublicKey can accept in one call; 0 before a key pair exists.
    int GetMaxAsymmetricPlaintextSize(void) const;

    // Exact ciphertext size EncryptWithPublicKey produces; 0 before a key pair exists.
    int GetAsymmetricCiphertextSize(void) const;

    // Typical use is wrapping a small symmetric key, not general-purpose data encryption --
    // inputBufferSize is bounded by GetMaxAsymmetricPlaintextSize(). No chunking, no password.
    int EncryptWithPublicKey( const unsigned char* inputBuffer, const int inputBufferSize,
                             const int outputBufferCapacity,
                             unsigned char* outputBuffer,
                             int* outputBufferSize);

    int DecryptWithPrivateKey( const unsigned char* inputBuffer, const int inputBufferSize,
                              const int outputBufferCapacity,
                              unsigned char* outputBuffer,
                              int* outputBufferSize);

    // Legacy cipher (CBC/CFB/ECB/RC2/DES/3DES/RC4, see the 4-argument constructor) has no
    // built-in integrity tag, so this adds Encrypt-then-MAC (HMAC-SHA256) on top: password derives
    // both the cipher key and the MAC key (single PBKDF2 call, split). Output layout is
    // [salt][iv][ciphertext][HMAC tag]; iv is omitted (0 bytes) for algorithms with no IV (ECB).
    // No chunking -- inputBufferSize is bounded by available memory in one call, not a fixed limit.
    int EncryptLegacyBuffer( const char* password, const int passwordSize,
                            const unsigned char* inputBuffer, const int inputBufferSize,
                            const int outputBufferCapacity,
                            unsigned char* outputBuffer,
                            int* outputBufferSize);

    // Verifies the HMAC tag before decrypting anything (fail-closed): a tampered or truncated
    // input returns INVALID_DATA and never reaches the legacy cipher.
    int DecryptLegacyBuffer( const char* password, const int passwordSize,
                            const unsigned char* inputBuffer, const int inputBufferSize,
                            const int outputBufferCapacity,
                            unsigned char* outputBuffer,
                            int* outputBufferSize);

    // ============================================================================================
    // Hash (message digest) -- see HashAlgorithm in ProviderTypes.h and the 5-argument constructor.
    // No key or password: these only digest the input. Output size is fixed per algorithm (see
    // GetHashSize) regardless of input size, so the BUFFER_TOO_SMALL capacity-query convention
    // below always reports the same constant for a given instance.
    // ============================================================================================

    // Exact digest size ComputeHashBuffer/ComputeHashBytes/ComputeHashString/ComputeHashFile
    // produce for this instance's hashAlgorithm_; 0 if the algorithm is unsupported by
    // providerKind_.
    int GetHashSize(void) const;

    // Buffers contain raw bytes. Input is processed in chunks so large buffers report progress;
    // onProgress may be nullptr.
    int ComputeHashBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                          const int outputBufferCapacity,
                          unsigned char* outputBuffer,
                          int* outputBufferSize,
                          ProgressCallback onProgress,
                          void* progressUserData);

    // Alias of ComputeHashBuffer with an identical chunked implementation.
    int ComputeHashBytes( const unsigned char* inputBuffer, const int inputBufferSize,
                         const int outputBufferCapacity,
                         unsigned char* outputBuffer,
                         int* outputBufferSize,
                         ProgressCallback onProgress,
                         void* progressUserData);

    // String input uses UTF-8 bytes. Input is processed in chunks so large strings report
    // progress; onProgress may be nullptr.
    int ComputeHashString( const char* inputString, const int inputStringSize,
                          const int outputBufferCapacity,
                          unsigned char* outputBuffer,
                          int* outputBufferSize,
                          ProgressCallback onProgress,
                          void* progressUserData);

    // File path is a UTF-8 string. Processed in chunks the same way EncryptFile/DecryptFile are
    // (see FILE_CHUNK_SIZE), so the whole file is never held in memory at once. onProgress may be
    // nullptr; when provided it is invoked after each processed chunk with cumulative bytes and
    // percentage complete.
    int ComputeHashFile( const char* inputFilePath,
                        const int outputBufferCapacity,
                        unsigned char* outputBuffer,
                        int* outputBufferSize,
                        ProgressCallback onProgress,
                        void* progressUserData);

    // ============================================================================================
    // Signature (sign/verify) -- see SignatureAlgorithm in ProviderTypes.h and the 6-argument
    // constructor. No password: GenerateSignatureKeyPair() creates a fresh key pair, the private
    // key never leaves this instance. This SDK does not yet support importing a third party's
    // public key to verify their signatures -- only self-contained sign-then-verify round trips
    // with a key pair this instance generated itself (see future_signing_key_agreement memory).
    // ============================================================================================

    // Generates a fresh key pair for this instance's signatureAlgorithm_. Must be called once
    // before SignBuffer/VerifyBuffer/GetSignatureSize; calling it again rotates to a fresh key
    // pair (old signatures become unverifiable against this instance).
    int GenerateSignatureKeyPair(void);

    // Exact signature size SignBuffer produces; 0 before a key pair exists.
    int GetSignatureSize(void) const;

    // Signs inputBuffer with the private key. No chunking, no password -- the provider hashes the
    // whole buffer internally as part of the signature scheme (SHA-256 for RSA-PSS/ECDSA, Ed25519's
    // own hashing for SIGNATURE_ED25519).
    int SignBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                    const int outputBufferCapacity,
                    unsigned char* outputBuffer,
                    int* outputBufferSize);

    // Verifies signatureBuffer against inputBuffer with this instance's public key. Returns
    // NO_ERROR when verification executed (isValid then reports whether the signature is
    // cryptographically valid) or an error code when verification could not run at all (no key
    // pair, invalid arguments); *isValid is only meaningful when the return value is NO_ERROR.
    // Kept separate from the return code so "couldn't verify" is never confused with "verified
    // and found invalid" -- a tampered signature must never look like a technical error.
    int VerifyBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                     const unsigned char* signatureBuffer, const int signatureBufferSize,
                     bool* isValid);

    // ============================================================================================
    // Key agreement (Diffie-Hellman style) -- see KeyAgreementAlgorithm in ProviderTypes.h and the
    // 7-argument/key-agreement-only constructors. Unlike RSA/Signature above (both self-contained
    // round trips inside one instance), key agreement is inherently two-party: two SEPARATE
    // CCryptoApi instances (same providerKind and keyAgreementAlgorithm) each call
    // GenerateKeyAgreementKeyPair() once, exchange public keys via ExportKeyAgreementPublicKey(),
    // and each calls DeriveSharedSecret() with the OTHER instance's exported public key. Both
    // sides then hold byte-identical shared secrets. See IKeyAgreementService's own doc comment for
    // why a public key exported by one ProviderKind must not be fed to a different ProviderKind.
    // ============================================================================================

    // Generates a fresh key pair for this instance's keyAgreementAlgorithm_. Must be called once
    // before GetKeyAgreementPublicKeySize/GetSharedSecretSize/ExportKeyAgreementPublicKey/
    // DeriveSharedSecret; calling it again rotates to a fresh key pair (a shared secret already
    // derived from the old key pair is unaffected, but the peer must re-fetch the new public key
    // before a following DeriveSharedSecret() call on either side agrees again).
    int GenerateKeyAgreementKeyPair(void);

    // Exact public key size ExportKeyAgreementPublicKey() produces; 0 before a key pair exists.
    int GetKeyAgreementPublicKeySize(void) const;

    // Exact shared secret size DeriveSharedSecret() produces; 0 before a key pair exists.
    int GetSharedSecretSize(void) const;

    // Exports this instance's own public key, to be handed to the peer instance (see the section
    // comment above). No chunking, no password.
    int ExportKeyAgreementPublicKey( const int outputBufferCapacity,
                                    unsigned char* outputBuffer,
                                    int* outputBufferSize);

    // Combines this instance's private key with peerPublicKeyBuffer (as produced by the peer
    // instance's own ExportKeyAgreementPublicKey()) to compute the shared secret.
    int DeriveSharedSecret( const unsigned char* peerPublicKeyBuffer, const int peerPublicKeyBufferSize,
                           const int outputBufferCapacity,
                           unsigned char* outputBuffer,
                           int* outputBufferSize);

    // ============================================================================================
    // Random byte generation -- see RandomAlgorithm in ProviderTypes.h. Unlike every other section
    // above, this is NOT tied to any constructor argument or cached engine: it works on any
    // CCryptoApi instance regardless of which constructor created it (using only this instance's
    // fixed providerKind_), takes no password/key, and every call is fully independent (no state
    // persists between calls, matching RANDOM_SYSTEM's own already-stateless nature and this SDK's
    // Hash section's same "stateless per call" reasoning). Output size is always exactly
    // outputBufferSize (no encoding/tag overhead to size for), so neither overload uses the
    // BUFFER_TOO_SMALL capacity-query convention the rest of this class uses -- there is nothing to
    // query.
    // ============================================================================================

    // Equivalent to GenerateRandomBytes(RANDOM_SYSTEM, outputBuffer, outputBufferSize) below.
    int GenerateRandomBytes(unsigned char* outputBuffer, const int outputBufferSize);

    // Uses an explicit NIST SP 800-90A DRBG (RANDOM_HASH_DRBG/HMAC_DRBG/CTR_DRBG) instead of this
    // instance's provider's implicit system RNG; returns UNEXPECTED_ERROR if providerKind_ doesn't
    // support the requested randomAlgorithm (query ICryptoProviderFactory::SupportsRandomAlgorithm
    // first if that distinction matters to the caller).
    int GenerateRandomBytes( const RandomAlgorithm randomAlgorithm,
                            unsigned char* outputBuffer, const int outputBufferSize);

protected:

private:

    // Password-based layer: derives the key (salt + PBKDF2) and chunks the input (see
    // BUFFER_CHUNK_SIZE), calling the key-based encryptBuffer overload below once per chunk.
    // Used by: EncryptBuffer, EncryptBytes, EncryptString.
    int encryptBuffer( const char* password, const int passwordSize,
                       const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputBufferCapacity,
                       unsigned char* outputBuffer,
                       int* outputBufferSize,
                       ProgressCallback onProgress,
                       void* progressUserData);

    // Password-based layer: derives the key (salt + PBKDF2) and chunks the input (see
    // BUFFER_CHUNK_SIZE), calling the key-based decryptBuffer overload below once per chunk.
    // Used by: DecryptBuffer, DecryptBytes, DecryptString.
    int decryptBuffer( const char* password, const int passwordSize,
                       const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputBufferCapacity,
                       unsigned char* outputBuffer,
                       int* outputBufferSize,
                       ProgressCallback onProgress,
                       void* progressUserData);

    // Core layer: no KDF, no chunking; encrypts one already-chunk-sized buffer in a single AEAD
    // call with an already-derived key. Used by: encryptBuffer(password, ...) above (once per
    // chunk) and EncryptFile (once per chunk, using the key it derives itself from the password).
    int encryptBuffer( const unsigned char* key, const int keySize,
                       const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputBufferCapacity,
                       unsigned char* outputBuffer,
                       int* outputBufferSize);

    // Core layer: no KDF, no chunking; decrypts one already-chunk-sized buffer in a single AEAD
    // call with an already-derived key. Used by: decryptBuffer(password, ...) above (once per
    // chunk) and DecryptFile (once per chunk, using the key it derives itself from the password).
    int decryptBuffer( const unsigned char* key, const int keySize,
                       const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputBufferCapacity,
                       unsigned char* outputBuffer,
                       int* outputBufferSize);

    // Core layer for the Hash section: chunks inputBuffer (see BUFFER_CHUNK_SIZE) through
    // IHashService's incremental Init/Update/Final so progress can be reported, then writes the
    // single fixed-size digest to outputBuffer. Used by: ComputeHashBuffer, ComputeHashBytes,
    // ComputeHashString.
    int computeHash( const unsigned char* inputBuffer, const int inputBufferSize,
                     const int outputBufferCapacity,
                     unsigned char* outputBuffer,
                     int* outputBufferSize,
                     ProgressCallback onProgress,
                     void* progressUserData);

    // Shared implementation behind every GetShared() overload above: each overload first resolves
    // its own defaults into a complete 7-field CCryptoApiConfig (mirroring the defaults its
    // equivalent plain constructor above would use), then calls this. Looks up config in the
    // process-wide cache under a mutex; on a miss, constructs the new instance via the 7-argument
    // constructor (equivalent to any single-purpose constructor once defaults are resolved -- see
    // CCryptoApiConfig's own comment), caches it, and returns it.
    static CCryptoApi& getSharedImpl(const CCryptoApiConfig& config);

    // Provider/algorithm this instance uses for every Encrypt*/Decrypt* call; fixed for the
    // instance's lifetime (see CCryptoApi(const ProviderKind, const AeadAlgorithm)).
    ProviderKind providerKind_;
    AeadAlgorithm aeadAlgorithm_;

    // RSA algorithm this instance uses for GenerateAsymmetricKeyPair; fixed for the instance's
    // lifetime. asymmetricCipher_ is null until GenerateAsymmetricKeyPair() succeeds, and then
    // holds the key pair for the instance's lifetime (see EncryptWithPublicKey/
    // DecryptWithPrivateKey above).
    AsymmetricAlgorithm asymmetricAlgorithm_;
    std::unique_ptr<IAsymmetricCipher> asymmetricCipher_;

    // Legacy cipher this instance uses for EncryptLegacyBuffer/DecryptLegacyBuffer; fixed for the
    // instance's lifetime. Stateless per-call like the AEAD path (no cached cipher object) since,
    // unlike RSA, a fresh ILegacyCipher is cheap and each call derives its own key from the salt.
    LegacySymmetricAlgorithm legacyAlgorithm_;

    // Hash algorithm this instance uses for ComputeHashBuffer/ComputeHashBytes/ComputeHashString/
    // ComputeHashFile; fixed for the instance's lifetime. Stateless per-call like the AEAD/Legacy
    // paths (no cached hash object) since a fresh IHashService is cheap to create.
    HashAlgorithm hashAlgorithm_;

    // Signature algorithm this instance uses for GenerateSignatureKeyPair; fixed for the
    // instance's lifetime. signatureEngine_ is null until GenerateSignatureKeyPair() succeeds,
    // and then holds the key pair for the instance's lifetime (see SignBuffer/VerifyBuffer
    // above) -- cached like asymmetricCipher_ above, not stateless per-call, since key generation
    // is the expensive part and both Sign and Verify need the same key pair to be meaningful.
    SignatureAlgorithm signatureAlgorithm_;
    std::unique_ptr<ISignatureEngine> signatureEngine_;

    // Key agreement algorithm this instance uses for GenerateKeyAgreementKeyPair; fixed for the
    // instance's lifetime. keyAgreementEngine_ is null until GenerateKeyAgreementKeyPair()
    // succeeds, and then holds the key pair for the instance's lifetime (see
    // ExportKeyAgreementPublicKey/DeriveSharedSecret above) -- cached like signatureEngine_/
    // asymmetricCipher_ above, not stateless per-call, since key generation is the expensive part
    // and the exported public key must stay tied to the same private key across calls.
    KeyAgreementAlgorithm keyAgreementAlgorithm_;
    std::unique_ptr<IKeyAgreementService> keyAgreementEngine_;

};

} // namespace CryptoApiNS

#endif

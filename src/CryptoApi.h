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

class CCryptoApi
{
public:
    virtual ~CCryptoApi();
             CCryptoApi();
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm);

    // Hash-only: for callers who only need ComputeHashBuffer/ComputeHashBytes/ComputeHashString/
    // ComputeHashFile and never touch Encrypt*/Decrypt*/RSA/Legacy at all. aeadAlgorithm_/
    // asymmetricAlgorithm_/legacyAlgorithm_ still get sane defaults (see CryptoApi.cpp) so every
    // other method stays well-defined if called anyway, but this constructor's whole point is that
    // a hash-only caller never needs to think about them. Distinguishable from the 2-argument AEAD
    // constructor above by the 2nd parameter's type (HashAlgorithm vs AeadAlgorithm are distinct
    // enum types, so there is no overload ambiguity).
             CCryptoApi(const ProviderKind providerKind, const HashAlgorithm hashAlgorithm);

             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm);
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm);
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm);

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

};

} // namespace CryptoApiNS

#endif

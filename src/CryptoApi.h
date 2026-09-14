#ifndef AYCRYPTO_CRYPTO_API_H
#define AYCRYPTO_CRYPTO_API_H

#define CRYPTOAPI_VERSION_MAJOR 0
#define CRYPTOAPI_VERSION_MINOR 1
#define CRYPTOAPI_VERSION_BUILD_NUMBER 0
#define CRYPTOAPI_BUILD_DATE_RAW __DATE__
#define CRYPTOAPI_BUILD_TIME __TIME__

#include "Definitions/Definitions.h"
#include "Providers/ProviderTypes.h"

namespace CryptoApiNS
{

class CCryptoApi
{
public:
    virtual ~CCryptoApi();
             CCryptoApi();
             CCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm);

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

    // Provider/algorithm this instance uses for every Encrypt*/Decrypt* call; fixed for the
    // instance's lifetime (see CCryptoApi(const ProviderKind, const AeadAlgorithm)).
    ProviderKind providerKind_;
    AeadAlgorithm aeadAlgorithm_;

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_ICRYPTO_API_H
#define CRYPTOAPI_ICRYPTO_API_H

#include "Definitions/Definitions.h"
#include "Providers/ProviderTypes.h"

namespace CryptoApiNS
{

// Pure-virtual mirror of CCryptoApi's instance methods (see CryptoApi.h for the full documentation
// of each method -- not repeated here to avoid drift between the two). Exists so a CCryptoApi
// instance created inside a DLL (via CreateCryptoApi(), see CryptoApiFactory.h) can be used by a
// caller that only dynamically loaded that DLL (LoadLibrary/GetProcAddress, see
// DllLoader/CryptoApiDllLoader.h) instead of linking against it at compile time: virtual dispatch
// resolves through the vtable at runtime, so no call here needs the callee's mangled symbol to be
// resolved by the linker. CCryptoApi's static factory methods (GetShared/Instance/ResetShared) and
// its constructors are intentionally NOT part of this interface -- construction only ever happens
// on the CCryptoApi side (inside CreateCryptoApi()), never through ICryptoApi itself.
class ICryptoApi
{
public:
    virtual ~ICryptoApi();
             ICryptoApi();

    virtual const char* GetVersion(void) const = 0;

    virtual int EncryptBuffer( const char* password, const int passwordSize,
                               const unsigned char* inputBuffer, const int inputBufferSize,
                               const int outputBufferCapacity,
                               unsigned char* outputBuffer,
                               int* outputBufferSize,
                               ProgressCallback onProgress,
                               void* progressUserData) = 0;

    virtual int DecryptBuffer( const char* password, const int passwordSize,
                               const unsigned char* inputBuffer, const int inputBufferSize,
                               const int outputBufferCapacity,
                               unsigned char* outputBuffer,
                               int* outputBufferSize,
                               ProgressCallback onProgress,
                               void* progressUserData) = 0;

    virtual int EncryptBytes( const char* password, const int passwordSize,
                              const unsigned char* inputBuffer, const int inputBufferSize,
                              const int outputBufferCapacity,
                              unsigned char* outputBuffer,
                              int* outputBufferSize,
                              ProgressCallback onProgress,
                              void* progressUserData) = 0;

    virtual int DecryptBytes( const char* password, const int passwordSize,
                              const unsigned char* inputBuffer, const int inputBufferSize,
                              const int outputBufferCapacity,
                              unsigned char* outputBuffer,
                              int* outputBufferSize,
                              ProgressCallback onProgress,
                              void* progressUserData) = 0;

    virtual int EncryptString( const char* password, const int passwordSize,
                               const char* inputString, const int inputStringSize,
                               const int outputBufferCapacity,
                               unsigned char* outputBuffer,
                               int* outputBufferSize,
                               ProgressCallback onProgress,
                               void* progressUserData) = 0;

    virtual int DecryptString( const char* password, const int passwordSize,
                               const unsigned char* inputBuffer, const int inputBufferSize,
                               const int outputStringBufferCapacity,
                               char* outputStringBuffer,
                               int* outputStringSize,
                               ProgressCallback onProgress,
                               void* progressUserData) = 0;

    virtual int EncryptFile( const char* password,
                             const char* inputFilePath,
                             const char* outputFilePath,
                             ProgressCallback onProgress,
                             void* progressUserData) = 0;

    virtual int DecryptFile( const char* password,
                             const char* inputFilePath,
                             const char* outputFilePath,
                             ProgressCallback onProgress,
                             void* progressUserData) = 0;

    virtual int GenerateAsymmetricKeyPair(void) = 0;

    virtual int GetMaxAsymmetricPlaintextSize(void) const = 0;

    virtual int GetAsymmetricCiphertextSize(void) const = 0;

    virtual int EncryptWithPublicKey( const unsigned char* inputBuffer, const int inputBufferSize,
                                      const int outputBufferCapacity,
                                      unsigned char* outputBuffer,
                                      int* outputBufferSize) = 0;

    virtual int DecryptWithPrivateKey( const unsigned char* inputBuffer, const int inputBufferSize,
                                       const int outputBufferCapacity,
                                       unsigned char* outputBuffer,
                                       int* outputBufferSize) = 0;

    virtual int EncryptLegacyBuffer( const char* password, const int passwordSize,
                                     const unsigned char* inputBuffer, const int inputBufferSize,
                                     const int outputBufferCapacity,
                                     unsigned char* outputBuffer,
                                     int* outputBufferSize) = 0;

    virtual int DecryptLegacyBuffer( const char* password, const int passwordSize,
                                     const unsigned char* inputBuffer, const int inputBufferSize,
                                     const int outputBufferCapacity,
                                     unsigned char* outputBuffer,
                                     int* outputBufferSize) = 0;

    virtual int GetHashSize(void) const = 0;

    virtual int ComputeHashBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                                   const int outputBufferCapacity,
                                   unsigned char* outputBuffer,
                                   int* outputBufferSize,
                                   ProgressCallback onProgress,
                                   void* progressUserData) = 0;

    virtual int ComputeHashBytes( const unsigned char* inputBuffer, const int inputBufferSize,
                                  const int outputBufferCapacity,
                                  unsigned char* outputBuffer,
                                  int* outputBufferSize,
                                  ProgressCallback onProgress,
                                  void* progressUserData) = 0;

    virtual int ComputeHashString( const char* inputString, const int inputStringSize,
                                   const int outputBufferCapacity,
                                   unsigned char* outputBuffer,
                                   int* outputBufferSize,
                                   ProgressCallback onProgress,
                                   void* progressUserData) = 0;

    virtual int ComputeHashFile( const char* inputFilePath,
                                const int outputBufferCapacity,
                                unsigned char* outputBuffer,
                                int* outputBufferSize,
                                ProgressCallback onProgress,
                                void* progressUserData) = 0;

    virtual int GenerateSignatureKeyPair(void) = 0;

    virtual int GetSignatureSize(void) const = 0;

    virtual int SignBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                            const int outputBufferCapacity,
                            unsigned char* outputBuffer,
                            int* outputBufferSize) = 0;

    virtual int VerifyBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                             const unsigned char* signatureBuffer, const int signatureBufferSize,
                             bool* isValid) = 0;

    virtual int GenerateKeyAgreementKeyPair(void) = 0;

    virtual int GetKeyAgreementPublicKeySize(void) const = 0;

    virtual int GetSharedSecretSize(void) const = 0;

    virtual int ExportKeyAgreementPublicKey( const int outputBufferCapacity,
                                             unsigned char* outputBuffer,
                                             int* outputBufferSize) = 0;

    virtual int DeriveSharedSecret( const unsigned char* peerPublicKeyBuffer, const int peerPublicKeyBufferSize,
                                    const int outputBufferCapacity,
                                    unsigned char* outputBuffer,
                                    int* outputBufferSize) = 0;

    virtual int GenerateRandomBytes(unsigned char* outputBuffer, const int outputBufferSize) = 0;

    virtual int GenerateRandomBytes( const RandomAlgorithm randomAlgorithm,
                                     unsigned char* outputBuffer, const int outputBufferSize) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_IPGP_ENGINE_WRAPPER_H
#define CRYPTOAPI_IPGP_ENGINE_WRAPPER_H

#include "Definitions/Definitions.h"

namespace CryptoApiNS
{

// Selects which RFC 4880 5.2.3.9 compression algorithm (or none) real gpg's own "--compress-algo"
// option applies, for the EncryptBuffer/EncryptStringArmored/EncryptBufferMultiRecipient/
// EncryptStringArmoredMultiRecipient overloads below that accept one. Moved here (rather than
// living in Pgp/PgpEngineWrapper.h, where it originated) for the same reason IPgpEngine.h holds
// PgpKeyAlgorithm/PgpFileCompressionAlgorithm/etc.: CPgpEngineWrapper's own header needs to include
// this interface header to derive from IPgpEngineWrapper, so this enum type cannot live in
// PgpEngineWrapper.h without creating a circular include. See CPgpEngineWrapper's own EncryptBuffer
// overload doc comment (Pgp/PgpEngineWrapper.h) for the exact numeric-value-to-algorithm mapping --
// not repeated here to avoid drift between the two.
enum PgpCompressionAlgorithm
{
    PGP_COMPRESSION_ALGORITHM_NONE  = 0,
    PGP_COMPRESSION_ALGORITHM_ZIP   = 1,
    PGP_COMPRESSION_ALGORITHM_ZLIB  = 2,
    PGP_COMPRESSION_ALGORITHM_BZIP2 = 3
};

// Pure-virtual mirror of CPgpEngineWrapper's instance methods (see Pgp/PgpEngineWrapper.h for the
// full documentation of each method -- not repeated here to avoid drift between the two). Exists so
// a CPgpEngineWrapper instance created inside a DLL (via CreatePgpEngineWrapper(), see
// CryptoApiFactory.h) can be used by a caller that only dynamically loaded that DLL instead of
// linking against it at compile time -- same reasoning as ICryptoApi/IPgpEngine.
// CPgpEngineWrapper's constructors (default/rsaKeyBits) are intentionally NOT part of this
// interface -- construction only ever happens on the CPgpEngineWrapper side (inside
// CreatePgpEngineWrapper(), which always default-constructs, same limitation CreatePgpEngine() has
// for CPgpEngine's own non-default constructors).
class IPgpEngineWrapper
{
public:
    virtual ~IPgpEngineWrapper();
             IPgpEngineWrapper();

    virtual bool IsGnuPgAvailable(void) const = 0;

    virtual int GenerateKeyPair( const char* userId, const int userIdSize,
                                const char* password, const int passwordSize) = 0;

    virtual int GenerateKeyPair( const char* userId, const int userIdSize,
                                const char* password, const int passwordSize,
                                const unsigned int expirationSeconds) = 0;

    virtual int GenerateKeyPairEcc( const char* userId, const int userIdSize,
                                   const char* password, const int passwordSize) = 0;

    virtual int GenerateKeyPairEcc( const char* userId, const int userIdSize,
                                   const char* password, const int passwordSize,
                                   const unsigned int expirationSeconds) = 0;

    virtual unsigned int GetKeyExpirationSeconds(void) const = 0;

    virtual int GetPublicKeyArmoredSize(void) const = 0;
    virtual int GetSecretKeyArmoredSize(void) const = 0;

    virtual int ExportPublicKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;
    virtual int ExportSecretKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int GetKeyId(char* outputBuffer, const int outputBufferCapacity) const = 0;

    virtual int RevokeKeyArmored( const char* password, const int passwordSize,
                                 const unsigned char reasonCode, const char* reasonText, const int reasonTextSize,
                                 const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int ImportPeerPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize) = 0;

    virtual int GetPeerKeyId(char* outputBuffer, const int outputBufferCapacity) const = 0;

    virtual int GetImportedPeerKeyCount(void) const = 0;

    virtual int GetImportedPeerKeyId(const int peerIndex, char* outputBuffer, const int outputBufferCapacity) const = 0;

    virtual int GetKeyringListing(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const = 0;

    virtual int GetKeyringKeyCount(void) const = 0;

    virtual int GetKeyringKeyId(const int keyIndex, char* outputBuffer, const int outputBufferCapacity) const = 0;

    virtual int DeletePeerPublicKey(const char* keyId, const int keyIdSize) = 0;

    virtual int DeleteOwnIdentity(void) = 0;

    virtual int EncryptBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                              const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                              const PgpCompressionAlgorithm compressionAlgorithm,
                              const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptStringArmored( const char* inputString, const int inputStringSize,
                                     const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptStringArmored( const char* inputString, const int inputStringSize,
                                     const PgpCompressionAlgorithm compressionAlgorithm,
                                     const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptBufferSymmetric( const char* passphrase, const int passphraseSize,
                                       const unsigned char* inputBuffer, const int inputBufferSize,
                                       const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptStringArmoredSymmetric( const char* passphrase, const int passphraseSize,
                                              const char* inputString, const int inputStringSize,
                                              const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptBufferMultiRecipient( const unsigned char* inputBuffer, const int inputBufferSize,
                                            const char* const* recipientKeyIds, const int recipientCount,
                                            const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptBufferMultiRecipient( const unsigned char* inputBuffer, const int inputBufferSize,
                                            const char* const* recipientKeyIds, const int recipientCount,
                                            const PgpCompressionAlgorithm compressionAlgorithm,
                                            const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptStringArmoredMultiRecipient( const char* inputString, const int inputStringSize,
                                                   const char* const* recipientKeyIds, const int recipientCount,
                                                   const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptStringArmoredMultiRecipient( const char* inputString, const int inputStringSize,
                                                   const char* const* recipientKeyIds, const int recipientCount,
                                                   const PgpCompressionAlgorithm compressionAlgorithm,
                                                   const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int DecryptBuffer( const char* password, const int passwordSize,
                              const unsigned char* inputBuffer, const int inputBufferSize,
                              const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int DecryptStringArmored( const char* password, const int passwordSize,
                                    const char* inputString, const int inputStringSize,
                                    const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int SignBuffer( const char* password, const int passwordSize,
                           const unsigned char* inputBuffer, const int inputBufferSize,
                           const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int VerifyBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                             const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid) = 0;

    virtual int ClearSignString( const char* password, const int passwordSize,
                                const char* inputString, const int inputStringSize,
                                const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int VerifyClearSignedString(const char* clearSignedString, const int clearSignedStringSize, bool* isValid) = 0;

    virtual int EncryptFile( const char* inputFilePath, const char* outputFilePath,
                            ProgressCallback onProgress, void* progressUserData) = 0;

    virtual int DecryptFile( const char* password, const int passwordSize,
                            const char* inputFilePath, const char* outputFilePath,
                            ProgressCallback onProgress, void* progressUserData) = 0;

    virtual int SignFile( const char* password, const int passwordSize,
                        const char* inputFilePath, const char* signatureFilePath,
                        ProgressCallback onProgress, void* progressUserData) = 0;

    virtual int VerifyFile( const char* inputFilePath, const char* signatureFilePath,
                          bool* isValid, ProgressCallback onProgress, void* progressUserData) = 0;

    virtual int IsPublicKeyEncrypted( const unsigned char* inputBuffer, const int inputBufferSize,
                                     bool* isPublicKeyEncrypted) const = 0;

    virtual int IsPasswordEncrypted( const unsigned char* inputBuffer, const int inputBufferSize,
                                    bool* isPasswordEncrypted) const = 0;

    virtual int IsIntegrityProtected( const unsigned char* inputBuffer, const int inputBufferSize,
                                     bool* isIntegrityProtected) const = 0;

    virtual int GetCompression( const unsigned char* inputBuffer, const int inputBufferSize,
                               int* compressionAlgorithm) const = 0;

    virtual int ListEncryptionKeyIds( const unsigned char* inputBuffer, const int inputBufferSize,
                                     const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                                     int* keyIdCount) const = 0;

    virtual int ListSigningKeyIds( const unsigned char* inputBuffer, const int inputBufferSize,
                                  const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                                  int* keyIdCount) const = 0;

    virtual int ListSignatures( const unsigned char* inputBuffer, const int inputBufferSize,
                               const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                               int* signatureCount) const = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

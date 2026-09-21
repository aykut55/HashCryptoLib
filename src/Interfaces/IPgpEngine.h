#ifndef CRYPTOAPI_IPGP_ENGINE_H
#define CRYPTOAPI_IPGP_ENGINE_H

#include "Definitions/Definitions.h"

namespace CryptoApiNS
{

// Which public-key algorithm family GenerateKeyPair() below uses for an instance's own identity.
// Moved here (rather than living in Pgp/PgpEngine.h, where it originated) for the same reason
// ProviderTypes.h is split out from CryptoApi.h: CPgpEngine's own header needs to include this
// interface header to derive from IPgpEngine, so the enum types GetKeyAlgorithm/
// EncryptFileCompressed return/accept cannot themselves live in PgpEngine.h without creating a
// circular include. See PgpEngine.h's own (now-removed) copy of this comment for the full RSA vs.
// Ed25519/X25519 identity-shape explanation -- not repeated here to avoid drift between the two.
enum PgpKeyAlgorithm
{
    PGP_KEY_ALGORITHM_RSA           = 0,
    PGP_KEY_ALGORITHM_ED25519_X25519 = 1
};

// Which RFC 4880 Compressed Data packet (tag 8, section 5.6) encoding EncryptFileCompressed uses --
// values match the OpenPGP compression algorithm registry (section 9.3) directly. Named
// PgpFileCompressionAlgorithm rather than PgpCompressionAlgorithm to avoid colliding with
// IPgpEngineWrapper.h's own like-named (but NONE/ZIP/ZLIB/BZIP2, gpg "--compress-algo") enum -- the
// two are unrelated types in the same namespace, and both headers are commonly included together.
enum PgpFileCompressionAlgorithm
{
    PGP_FILE_COMPRESSION_ALGORITHM_ZIP  = 1,
    PGP_FILE_COMPRESSION_ALGORITHM_ZLIB = 2
};

// The two negative sentinel values GetCompression() writes into its compressionAlgorithm
// out-parameter when there is no Compressed Data packet octet to report. See CPgpEngine's own
// GetCompression doc comment (Pgp/PgpEngine.h) for the full "not present" vs. "unknown, needs
// decryption" distinction.
enum PgpCompressionInspectionResult
{
    PGP_COMPRESSION_NOT_PRESENT              = -1,
    PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION = -2
};

// Fixed per-record byte sizes (NUL terminator included) of the packed, fixed-stride records the
// three List* inspection methods below write into the caller's output buffer. See CPgpEngine's own
// doc comment (Pgp/PgpEngine.h) for the exact record layout.
enum PgpInspectionRecordSize
{
    PGP_INSPECTION_KEY_ID_RECORD_SIZE    = 17,
    PGP_INSPECTION_SIGNATURE_RECORD_SIZE = 23
};

// Pure-virtual mirror of CPgpEngine's instance methods (see Pgp/PgpEngine.h for the full
// documentation of each method -- not repeated here to avoid drift between the two). Exists so a
// CPgpEngine instance created inside a DLL (via CreatePgpEngine(), see CryptoApiFactory.h) can be
// used by a caller that only dynamically loaded that DLL (LoadLibrary/GetProcAddress, see
// DllLoader/CryptoApiDllLoader.h) instead of linking against it at compile time -- same reasoning
// as ICryptoApi. CPgpEngine's constructors (default/rsaKeyBits/keyAlgorithm) are intentionally NOT
// part of this interface -- construction only ever happens on the CPgpEngine side (inside
// CreatePgpEngine(), which always default-constructs -- see that function's own comment for why the
// two non-default constructors are unreachable through the DLL boundary, same limitation
// CreateCryptoApi() already has for CCryptoApi's many constructor overloads).
class IPgpEngine
{
public:
    virtual ~IPgpEngine();
             IPgpEngine();

    virtual PgpKeyAlgorithm GetKeyAlgorithm(void) const = 0;

    virtual int GenerateKeyPair( const char* userId, const int userIdSize,
                                const char* password, const int passwordSize) = 0;

    virtual int GenerateKeyPair( const char* userId, const int userIdSize,
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

    virtual int ImportAdditionalRecipientPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize) = 0;

    virtual int EncryptBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                              const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptStringArmored( const char* inputString, const int inputStringSize,
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

    virtual int EncryptFileCompressed( const char* inputFilePath, const char* outputFilePath,
                                      const PgpFileCompressionAlgorithm compressionAlgorithm,
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

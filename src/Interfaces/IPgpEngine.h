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

    // Full RFC 4880 v4 fingerprint (40 hex chars, no separators) of this instance's own master key
    // -- GetKeyId above returns only the low 16 hex chars (8 bytes) of this same fingerprint.
    // outputBufferCapacity must be >= 41. Empty string before GenerateKeyPair succeeds, same
    // convention as GetKeyId.
    virtual int GetKeyFingerprint(char* outputBuffer, const int outputBufferCapacity) const = 0;

    virtual int RevokeKeyArmored( const char* password, const int passwordSize,
                                 const unsigned char reasonCode, const char* reasonText, const int reasonTextSize,
                                 const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    // -- Own-identity UID management (multi-UID support, gpg --edit-key adduid/deluid/primary parity) --
    virtual int AddUserId(const char* password, const int passwordSize, const char* userId, const int userIdSize, const bool makePrimary) = 0;

    // deluid equivalent: revokes (does not delete) the UID at userIdIndex -- matches real gpg's own
    // current behavior of layering a 0x30 revocation signature over the existing self-cert rather
    // than removing the UID packet, since hard-deleting a UID breaks third-party certifications on it.
    virtual int RevokeUserId(const char* password, const int passwordSize, const int userIdIndex, const unsigned char reasonCode, const char* reasonText, const int reasonTextSize) = 0;

    virtual int SetPrimaryUserId(const char* password, const int passwordSize, const int userIdIndex) = 0;

    virtual int GetUserIdCount(void) const = 0;
    virtual int GetUserId(const int userIdIndex, char* outputBuffer, const int outputBufferCapacity, int* outputBufferSize) const = 0;
    virtual int GetUserIdIsPrimary(const int userIdIndex, bool* isPrimary) const = 0;
    virtual int GetUserIdIsRevoked(const int userIdIndex, bool* isRevoked) const = 0;

    // -- Own-identity subkey management (multi-subkey support, gpg --edit-key addkey/expire parity) --
    // No algorithm parameter -- a new subkey always matches this instance's own fixed key-algorithm
    // family (see GetKeyAlgorithm above). keyFlags follows RFC 4880 5.2.3.21: 0x02 sign, 0x0C
    // encrypt, 0x20 authenticate. On an Ed25519/X25519-family instance only 0x0C (encrypt, producing
    // an additional X25519 subkey) is currently supported -- any other flags value returns
    // NOT_IMPLEMENTED, since a sign/auth subkey there would need a separate Ed25519 (not X25519)
    // subkey code path this engine does not yet have.
    virtual int AddSubkey(const char* password, const int passwordSize, const unsigned char keyFlags, const unsigned int expirationSeconds) = 0;

    virtual int RevokeSubkey(const char* password, const int passwordSize, const int subkeyIndex, const unsigned char reasonCode, const char* reasonText, const int reasonTextSize) = 0;

    // subkeyIndex == -1 targets the primary key itself; otherwise an index into the own-subkey list.
    virtual int SetKeyExpiration(const char* password, const int passwordSize, const int subkeyIndex, const unsigned int expirationSeconds) = 0;

    virtual int GetSubkeyCount(void) const = 0;
    virtual int GetSubkeyKeyId(const int subkeyIndex, char* outputBuffer, const int outputBufferCapacity) const = 0;
    virtual int GetSubkeyFingerprint(const int subkeyIndex, char* outputBuffer, const int outputBufferCapacity) const = 0;
    virtual int GetSubkeyIsRevoked(const int subkeyIndex, bool* isRevoked) const = 0;
    virtual int GetSubkeyExpirationSeconds(const int subkeyIndex, unsigned int* expirationSeconds) const = 0;

    // passwd equivalent -- re-encrypts the own master key and every own subkey's secret material
    // under newPassword; oldPassword must match the identity's current password.
    virtual int ChangePassword(const char* oldPassword, const int oldPasswordSize, const char* newPassword, const int newPasswordSize) = 0;

    virtual int ImportPeerPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize) = 0;

    // Peer-identity enumeration -- mirrors the own-identity getters above, populated by
    // ImportPeerPublicKey once its parser collects every UID/subkey packet (not just the first of
    // each) from the imported public key block.
    virtual int GetPeerUserIdCount(void) const = 0;
    virtual int GetPeerUserId(const int userIdIndex, char* outputBuffer, const int outputBufferCapacity, int* outputBufferSize) const = 0;
    virtual int GetPeerSubkeyCount(void) const = 0;
    virtual int GetPeerSubkeyKeyId(const int subkeyIndex, char* outputBuffer, const int outputBufferCapacity) const = 0;

    virtual int GetPeerKeyId(char* outputBuffer, const int outputBufferCapacity) const = 0;

    virtual int ImportAdditionalRecipientPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize) = 0;

    virtual int EncryptBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                              const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptStringArmored( const char* inputString, const int inputStringSize,
                                     const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    // Combined sign+encrypt -- real gpg's own default "--sign --encrypt" wire format (One-Pass-
    // Signature + Literal Data + Signature, all inside the SAME compressed+encrypted container),
    // NOT the same as calling EncryptBuffer/SignBuffer separately (two independent messages).
    // Requires both an own identity (signing) and an imported peer key (encryption recipient).
    virtual int EncryptAndSignBuffer( const char* password, const int passwordSize,
                                     const unsigned char* inputBuffer, const int inputBufferSize,
                                     const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int EncryptAndSignStringArmored( const char* password, const int passwordSize,
                                            const char* inputString, const int inputStringSize,
                                            const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) = 0;

    virtual int DecryptBuffer( const char* password, const int passwordSize,
                              const unsigned char* inputBuffer, const int inputBufferSize,
                              const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    virtual int DecryptStringArmored( const char* password, const int passwordSize,
                                    const char* inputString, const int inputStringSize,
                                    const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    // Counterpart to EncryptAndSignBuffer/EncryptAndSignStringArmored above -- decrypts AND
    // requires/verifies an embedded (one-pass) signature. Returns INVALID_DATA if the decrypted
    // content carries no signature at all (a plain encrypted-only message is a structural mismatch
    // for this method -- use DecryptBuffer/DecryptStringArmored instead). isSignatureValid is only
    // meaningful when the return value is NO_ERROR.
    virtual int DecryptAndVerifyBuffer( const char* password, const int passwordSize,
                                       const unsigned char* inputBuffer, const int inputBufferSize,
                                       const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize,
                                       bool* isSignatureValid) = 0;

    virtual int DecryptAndVerifyStringArmored( const char* password, const int passwordSize,
                                              const char* inputString, const int inputStringSize,
                                              const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize,
                                              bool* isSignatureValid) = 0;

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

    // Human-readable, gpg-`--list-packets`-style text dump combining everything the Is*/List*
    // methods above already extract into one report. Envelope-only, same limitation as those
    // methods -- packets inside an encrypted (SEIP/AEAD) container are not visible without
    // decrypting first.
    virtual int ListPackets( const unsigned char* inputBuffer, const int inputBufferSize,
                            const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

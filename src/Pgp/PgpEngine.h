#ifndef AYCRYPTO_PGP_ENGINE_H
#define AYCRYPTO_PGP_ENGINE_H

#include "Definitions/Definitions.h"

#include <memory>

namespace CryptoApiNS
{

class CPgpEngine
{
public:
    virtual ~CPgpEngine();
             CPgpEngine();

    // rsaKeyBits selects the RSA key size GenerateKeyPair() below will use (1024/2048/3072/4096);
    // any other value is rejected by GenerateKeyPair() with INVALID_ARGUMENT.
    explicit CPgpEngine(const int rsaKeyBits);

    // ============================================================================================
    // Identity (own key pair) -- RFC 4880 v4 keys: one RSA master key (Sign+Certify, key flags
    // 0x03) plus one RSA encryption subkey (Encrypt, key flags 0x0C), bound to userId by a 0x13
    // positive-certification self-signature (SHA-256). password protects the exported secret key
    // material (S2K, iterated+salted, SHA-256) -- it is NOT the same as any per-message password.
    // Must be called once before ExportPublicKeyArmored/ExportSecretKeyArmored/DecryptBuffer/
    // DecryptStringArmored/SignBuffer/ClearSignString; calling it again rotates to a fresh
    // identity (old exported keys/signatures become unrelated to the new one).
    // ============================================================================================

    int GenerateKeyPair( const char* userId, const int userIdSize,
                        const char* password, const int passwordSize);

    // Same as the 4-argument overload above, plus a Key Expiration Time subpacket (RFC 4880
    // 5.2.3.6, type 9) on both the self-certification and subkey-binding signatures:
    // expirationSeconds is how many seconds after this call's creation timestamp the key expires;
    // 0 means never expires (identical behavior to the 4-argument overload, which delegates here
    // with 0).
    int GenerateKeyPair( const char* userId, const int userIdSize,
                        const char* password, const int passwordSize,
                        const unsigned int expirationSeconds);

    // What GenerateKeyPair's expirationSeconds argument was last called with (0 if never called,
    // or if the 4-argument overload -- which always means "never expires" -- was used).
    unsigned int GetKeyExpirationSeconds(void) const;

    // Exact ASCII-armored size ExportPublicKeyArmored/ExportSecretKeyArmored would need; 0 before
    // GenerateKeyPair() succeeds. capacity=0/buffer=nullptr queries the required size (see
    // BUFFER_TOO_SMALL convention on the methods below).
    int GetPublicKeyArmoredSize(void) const;
    int GetSecretKeyArmoredSize(void) const;

    // "-----BEGIN PGP PUBLIC KEY BLOCK-----": master key + encryption subkey + userId + both
    // binding signatures, no secret material.
    int ExportPublicKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize);

    // "-----BEGIN PGP PRIVATE KEY BLOCK-----": same packets as above plus both private keys,
    // S2K-protected with this instance's GenerateKeyPair() password.
    int ExportSecretKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize);

    // Hex Key ID (8 bytes / 16 hex chars + null terminator) of this instance's own master key;
    // empty string before GenerateKeyPair() succeeds. outputBufferCapacity must be >= 17.
    int GetKeyId(char* outputBuffer, const int outputBufferCapacity) const;

    // GenerateKeyPair() must have succeeded first; password must match the one it was called
    // with. Produces a standalone RFC 4880 key revocation certificate (signature type 0x20),
    // armored under "-----BEGIN PGP PUBLIC KEY BLOCK-----" (the same label a real public key
    // block uses -- this is standard OpenPGP/GnuPG convention for revocation certificates, since
    // importing one into a keyring is exactly how it gets applied). Importing the result into a
    // keyring that already holds this identity's public key marks that key as revoked; it does
    // NOT delete or invalidate this CPgpEngine instance's own in-memory key, which remains fully
    // usable for Sign/Encrypt/Decrypt calls after this returns. reasonCode: 0 = no reason
    // specified, 1 = key superseded, 2 = key compromised, 3 = key retired (RFC 4880 5.2.3.23);
    // reasonText may be nullptr/0-length for no human-readable reason.
    int RevokeKeyArmored( const char* password, const int passwordSize,
                         const unsigned char reasonCode, const char* reasonText, const int reasonTextSize,
                         const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize);

    // ============================================================================================
    // Peer key (the other party's public key) -- unlike GenerateKeyPair() above, this instance
    // never generates or holds a peer's PRIVATE key. Import once before EncryptBuffer/
    // EncryptStringArmored (encrypts to the peer's encryption subkey) or VerifyBuffer/
    // VerifyClearSignedString (verifies against the peer's master key). keyBlockBuffer may be
    // either ASCII-armored ("-----BEGIN PGP PUBLIC KEY BLOCK-----") or raw binary packets --
    // detected automatically from the first bytes.
    // ============================================================================================

    int ImportPeerPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize);

    // Hex Key ID of the most recently imported peer master key; empty string before
    // ImportPeerPublicKey() succeeds.
    int GetPeerKeyId(char* outputBuffer, const int outputBufferCapacity) const;

    // ============================================================================================
    // Encrypt (to the imported peer's encryption subkey) / Decrypt (with this instance's own
    // secret key) -- RFC 4880 single-recipient message: Public-Key Encrypted Session Key (tag 1,
    // RSA-PKCS#1v1.5) + Compressed Data (tag 8, ZIP) + Literal Data (tag 11), all wrapped in a
    // Sym. Encrypted Integrity Protected Data packet (tag 18, AES-256-CFB, SHA-1 MDC). Decrypt
    // fails closed (INVALID_DATA) on any MDC mismatch before returning partial plaintext.
    // ============================================================================================

    // ImportPeerPublicKey() must have succeeded first. No chunking -- inputBufferSize is bounded
    // by available memory in one call.
    int EncryptBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                      const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize);

    // Same as EncryptBuffer, ASCII-armored ("-----BEGIN PGP MESSAGE-----") text output instead of
    // raw binary.
    int EncryptStringArmored( const char* inputString, const int inputStringSize,
                             const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize);

    // GenerateKeyPair() must have succeeded first; password must match the one it was called
    // with. Decompresses ZIP/ZLIB/uncompressed literal bodies (whichever the sender used).
    int DecryptBuffer( const char* password, const int passwordSize,
                      const unsigned char* inputBuffer, const int inputBufferSize,
                      const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize);

    // Same as DecryptBuffer, ASCII-armored input instead of raw binary.
    int DecryptStringArmored( const char* password, const int passwordSize,
                            const char* inputString, const int inputStringSize,
                            const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize);

    // ============================================================================================
    // Sign (with this instance's own master key) / Verify (against the imported peer's master
    // key) -- detached RSA-PKCS#1v1.5-SHA256 signature packet (tag 2, signature type 0x00).
    // ============================================================================================

    // GenerateKeyPair() must have succeeded first; password must match the one it was called
    // with. No chunking, no compression.
    int SignBuffer( const char* password, const int passwordSize,
                   const unsigned char* inputBuffer, const int inputBufferSize,
                   const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize);

    // ImportPeerPublicKey() must have succeeded first. Returns NO_ERROR when verification
    // executed (isValid then reports whether the signature is cryptographically valid) or an
    // error code when verification could not run at all; *isValid is only meaningful when the
    // return value is NO_ERROR (same convention as CCryptoApi::VerifyBuffer).
    int VerifyBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                     const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid);

    // ============================================================================================
    // Clear-sign -- RFC 4880 section 7 framing ("-----BEGIN PGP SIGNED MESSAGE-----" / "Hash:
    // SHA256" / dash-escaped body / "-----BEGIN PGP SIGNATURE-----"), signature type 0x01
    // (canonical text document).
    // ============================================================================================

    // GenerateKeyPair() must have succeeded first; password must match the one it was called with.
    int ClearSignString( const char* password, const int passwordSize,
                        const char* inputString, const int inputStringSize,
                        const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize);

    // ImportPeerPublicKey() must have succeeded first. Same NO_ERROR/*isValid convention as
    // VerifyBuffer above.
    int VerifyClearSignedString(const char* clearSignedString, const int clearSignedStringSize, bool* isValid);

    // ============================================================================================
    // File-based streaming variants -- unlike EncryptBuffer/SignBuffer above (which hold the
    // whole input in memory in one shot), these process the file in fixed-size chunks so memory
    // use stays roughly constant regardless of file size, and report progress the same way
    // CCryptoApi::EncryptFile/DecryptFile do (onProgress may be nullptr; returning false aborts
    // with OPERATION_CANCELLED at the next chunk boundary). EncryptFile skips ZIP compression
    // (unlike EncryptBuffer) so every packet length is exactly known from the input file's size
    // before writing a single byte -- still valid, uncompressed OpenPGP, just not compressed.
    // DecryptFile writes to a temporary file first and only replaces outputFilePath with it if
    // the trailing MDC check passes: SEIP's MDC sits at the very end of the stream, so unlike
    // DecryptBuffer's one-shot version there is no way to verify integrity before starting to
    // write plaintext -- this mirrors GnuPG's own inherent limitation for streamed decryption,
    // not something specific to this engine.
    // ============================================================================================

    // ImportPeerPublicKey() must have succeeded first.
    int EncryptFile( const char* inputFilePath, const char* outputFilePath,
                    ProgressCallback onProgress, void* progressUserData);

    // GenerateKeyPair() must have succeeded first; password must match the one it was called
    // with. Decompresses a ZIP/ZLIB-compressed inner packet if present (e.g. from EncryptBuffer
    // or GnuPG), otherwise reads the uncompressed literal packet EncryptFile itself produces.
    int DecryptFile( const char* password, const int passwordSize,
                    const char* inputFilePath, const char* outputFilePath,
                    ProgressCallback onProgress, void* progressUserData);

    // GenerateKeyPair() must have succeeded first; password must match the one it was called
    // with. signatureFilePath receives the raw (non-armored) detached signature packet, same
    // format SignBuffer produces.
    int SignFile( const char* password, const int passwordSize,
                 const char* inputFilePath, const char* signatureFilePath,
                 ProgressCallback onProgress, void* progressUserData);

    // ImportPeerPublicKey() must have succeeded first. Same NO_ERROR/*isValid convention as
    // VerifyBuffer above.
    int VerifyFile( const char* inputFilePath, const char* signatureFilePath,
                   bool* isValid, ProgressCallback onProgress, void* progressUserData);

protected:

private:

    // CryptoPP types are kept out of this header so callers never need CryptoPP's own headers or
    // include path; only PgpEngine.cpp does (same pattern as CCryptoPPProvider).
    struct Impl;
    std::unique_ptr<Impl> impl_;

};

} // namespace CryptoApiNS

#endif

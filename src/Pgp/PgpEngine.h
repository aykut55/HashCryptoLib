#ifndef AYCRYPTO_PGP_ENGINE_H
#define AYCRYPTO_PGP_ENGINE_H

#include "Definitions/Definitions.h"

#include <memory>

namespace CryptoApiNS
{

// Which public-key algorithm family GenerateKeyPair() below uses for this instance's own identity
// -- fixed at construction (see the two constructors below), never changed afterward.
// PGP_KEY_ALGORITHM_RSA (the default -- also what the no-arg and rsaKeyBits constructors select)
// pairs an RSA master key with an RSA encryption subkey, exactly as documented on GenerateKeyPair
// itself. PGP_KEY_ALGORITHM_ED25519_X25519 instead pairs an Ed25519 (RFC 8032, OpenPGP algorithm
// ID 22, "EdDSA Legacy") master signing key with an X25519 (RFC 7748, OpenPGP algorithm ID 18,
// ECDH over Curve25519) encryption subkey -- the same "ed25519" default identity shape real GnuPG
// produces (verified by generating one with a local GnuPG install and inspecting its exported
// packets byte-for-byte), so identities from either implementation interoperate. Note this
// describes THIS instance's OWN identity only: the peer key imported via ImportPeerPublicKey/
// ImportAdditionalRecipientPublicKey below carries its own, independently-detected algorithm per
// key (RSA and Ed25519/X25519 peers can be mixed freely, including as multiple recipients of the
// same EncryptBuffer call).
enum PgpKeyAlgorithm
{
    PGP_KEY_ALGORITHM_RSA           = 0,
    PGP_KEY_ALGORITHM_ED25519_X25519 = 1
};

class CPgpEngine
{
public:
    virtual ~CPgpEngine();
             CPgpEngine();

    // rsaKeyBits selects the RSA key size GenerateKeyPair() below will use (1024/2048/3072/4096);
    // any other value is rejected by GenerateKeyPair() with INVALID_ARGUMENT. Selects
    // PGP_KEY_ALGORITHM_RSA (see GetKeyAlgorithm below).
    explicit CPgpEngine(const int rsaKeyBits);

    // Selects keyAlgorithm for this instance's own identity (see the PgpKeyAlgorithm comment
    // above); GenerateKeyPair() then generates that kind of key pair instead of RSA. There is no
    // key-size parameter for PGP_KEY_ALGORITHM_ED25519_X25519 -- Ed25519/X25519 both have exactly
    // one fixed size (RFC 8032/7748), unlike RSA. Passing PGP_KEY_ALGORITHM_RSA here is equivalent
    // to the rsaKeyBits constructor with 2048.
    explicit CPgpEngine(const PgpKeyAlgorithm keyAlgorithm);

    // Which algorithm this instance's own identity uses -- fixed at construction (see the two
    // constructors above), independent of whether GenerateKeyPair() has been called yet.
    PgpKeyAlgorithm GetKeyAlgorithm(void) const;

    // ============================================================================================
    // Identity (own key pair) -- RFC 4880 v4 keys: for PGP_KEY_ALGORITHM_RSA (the default), one
    // RSA master key (Sign+Certify, key flags 0x03) plus one RSA encryption subkey (Encrypt, key
    // flags 0x0C); for PGP_KEY_ALGORITHM_ED25519_X25519, one Ed25519 master key (same Sign+Certify
    // flags 0x03) plus one X25519 encryption subkey (same Encrypt flags 0x0C), self-certification
    // signed with Ed25519/SHA-512 instead of RSA/SHA-256 (matching what real GnuPG's own "ed25519"
    // identities use). Either way, bound to userId by a 0x13 positive-certification self-signature.
    // password protects the exported secret key material (S2K, iterated+salted, SHA-256) -- it is
    // NOT the same as any per-message password. Must be called once before
    // ExportPublicKeyArmored/ExportSecretKeyArmored/DecryptBuffer/DecryptStringArmored/
    // SignBuffer/ClearSignString; calling it again rotates to a fresh identity (old exported keys/
    // signatures become unrelated to the new one).
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

    // Adds ANOTHER recipient's public key to an internal list used ONLY by EncryptBuffer/
    // EncryptStringArmored/EncryptFile below -- never by VerifyBuffer/VerifyClearSignedString/
    // VerifyFile, which always verify against the single peer ImportPeerPublicKey set (this is the
    // multi-recipient extension of the single-peer model above: ImportPeerPublicKey's peer is
    // always included as one recipient automatically, so callers do not re-add it here). May be
    // called multiple times to add multiple additional recipients; every call so far (the
    // ImportPeerPublicKey peer plus every ImportAdditionalRecipientPublicKey addition) receives its
    // own Public-Key Encrypted Session Key (tag 1) packet in the NEXT Encrypt* call's output, all
    // of them wrapping the SAME randomly generated session key -- so any one recipient's matching
    // secret key can decrypt the result independently, exactly like a real multi-recipient OpenPGP
    // message. ImportPeerPublicKey() must have succeeded first (it establishes the primary peer);
    // keyBlockBuffer follows the same armored-or-binary auto-detection as ImportPeerPublicKey, and
    // the added recipient's own algorithm (RSA or Ed25519/X25519) is detected independently of both
    // this instance's own GetKeyAlgorithm() and the primary peer's -- recipients of different
    // algorithms may be mixed freely in the same call sequence. Encrypt* keeps working exactly as
    // before (single PKESK, to the ImportPeerPublicKey peer only) when this is never called.
    int ImportAdditionalRecipientPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize);

    // ============================================================================================
    // Encrypt (to the imported peer's encryption subkey, plus any ImportAdditionalRecipientPublicKey
    // recipients) / Decrypt (with this instance's own secret key) -- RFC 4880 message: one
    // Public-Key Encrypted Session Key (tag 1) packet per recipient (RSA-PKCS#1v1.5 or, for an
    // Ed25519/X25519 recipient, ECDH per RFC 6637/crypto-refresh -- ephemeral X25519 key agreement,
    // SHA-256 KDF, AES-128 RFC 3394 key wrap, matching real GnuPG's own Curve25519 defaults) +
    // Compressed Data (tag 8, ZIP) + Literal Data (tag 11), all wrapped in a single Sym. Encrypted
    // Integrity Protected Data packet (tag 18, AES-256-CFB, SHA-1 MDC) shared by every recipient.
    // Decrypt fails closed (INVALID_DATA) on any MDC mismatch before returning partial plaintext,
    // and (when there are multiple PKESK packets) tries each one in turn looking for the one
    // addressed to this instance's own Key ID rather than assuming the first PKESK is always ours.
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
    // key) -- detached signature packet (tag 2, signature type 0x00): RSA-PKCS#1v1.5-SHA256 for a
    // PGP_KEY_ALGORITHM_RSA identity/peer, or Ed25519-SHA512 (per crypto-refresh's EdDSA Legacy
    // convention, matching real GnuPG) for a PGP_KEY_ALGORITHM_ED25519_X25519 one -- SignBuffer
    // always uses THIS instance's own GetKeyAlgorithm(); VerifyBuffer detects the peer's algorithm
    // independently from the signature packet's own algorithm octet, so either engine can verify
    // either kind of signature regardless of its own identity's algorithm.
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
    // not something specific to this engine. Multi-recipient (ImportAdditionalRecipientPublicKey)
    // IS supported here for RSA recipients. v1 scope limitation: these four streaming methods
    // support PGP_KEY_ALGORITHM_RSA only -- EncryptFile returns NOT_IMPLEMENTED if this instance's
    // own algorithm, the ImportPeerPublicKey peer's encryption-subkey algorithm, or any
    // ImportAdditionalRecipientPublicKey recipient's algorithm is PGP_KEY_ALGORITHM_ED25519_X25519;
    // DecryptFile/SignFile return NOT_IMPLEMENTED when this instance's own algorithm is
    // PGP_KEY_ALGORITHM_ED25519_X25519; VerifyFile returns NOT_IMPLEMENTED when the
    // ImportPeerPublicKey peer's master-key algorithm is PGP_KEY_ALGORITHM_ED25519_X25519. The
    // buffer-based Encrypt/Decrypt/Sign/Verify/ClearSign methods above have no such restriction --
    // this gap is streaming-path-only, deferred for scope/time (see CPgpEngine.cpp's own comment
    // on these four methods for the reasoning).
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

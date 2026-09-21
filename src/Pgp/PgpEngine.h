#ifndef AYCRYPTO_PGP_ENGINE_H
#define AYCRYPTO_PGP_ENGINE_H

#include "Definitions/Definitions.h"
#include "Interfaces/IPgpEngine.h"

#include <memory>

// DLL export/import boundary for CPgpEngine as a real C++ class -- same reasoning and same macro
// name as CryptoApi.h's own CRYPTOAPI_API (redefining it identically here is harmless: both headers
// are commonly included in the same translation unit, e.g. ScriptPgpEngine.cpp, and an identical
// macro redefinition is not an error). DllBuilder defines CRYPTOAPI_DLL_EXPORTS so its own compile
// exports the class; a future consumer linking against the DLL at compile time (rather than through
// CreatePgpEngine()/IPgpEngine, see CryptoApiFactory.h) would define CRYPTOAPI_DLL_IMPORTS to
// import it instead. Neither macro is defined when this header is compiled directly into an
// executable or a static library (AppBuilder, LibBuilder), so CRYPTOAPI_API expands to nothing
// there.
#if defined(CRYPTOAPI_DLL_EXPORTS)
#define CRYPTOAPI_API __declspec(dllexport)
#elif defined(CRYPTOAPI_DLL_IMPORTS)
#define CRYPTOAPI_API __declspec(dllimport)
#else
#define CRYPTOAPI_API
#endif

namespace CryptoApiNS
{

// C4251/C4275: see CryptoApi.h's own identical pragma block for why both are harmless here --
// impl_ is private and never touched across the DLL boundary, and IPgpEngine (this class's base)
// declares no data and no non-inline code of its own.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4251)
#pragma warning(disable: 4275)
#endif

class CRYPTOAPI_API CPgpEngine : public IPgpEngine
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
    PgpKeyAlgorithm GetKeyAlgorithm(void) const override;

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
                        const char* password, const int passwordSize) override;

    // Same as the 4-argument overload above, plus a Key Expiration Time subpacket (RFC 4880
    // 5.2.3.6, type 9) on both the self-certification and subkey-binding signatures:
    // expirationSeconds is how many seconds after this call's creation timestamp the key expires;
    // 0 means never expires (identical behavior to the 4-argument overload, which delegates here
    // with 0).
    int GenerateKeyPair( const char* userId, const int userIdSize,
                        const char* password, const int passwordSize,
                        const unsigned int expirationSeconds) override;

    // What GenerateKeyPair's expirationSeconds argument was last called with (0 if never called,
    // or if the 4-argument overload -- which always means "never expires" -- was used).
    unsigned int GetKeyExpirationSeconds(void) const override;

    // Exact ASCII-armored size ExportPublicKeyArmored/ExportSecretKeyArmored would need; 0 before
    // GenerateKeyPair() succeeds. capacity=0/buffer=nullptr queries the required size (see
    // BUFFER_TOO_SMALL convention on the methods below).
    int GetPublicKeyArmoredSize(void) const override;
    int GetSecretKeyArmoredSize(void) const override;

    // "-----BEGIN PGP PUBLIC KEY BLOCK-----": master key + encryption subkey + userId + both
    // binding signatures, no secret material.
    int ExportPublicKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // "-----BEGIN PGP PRIVATE KEY BLOCK-----": same packets as above plus both private keys,
    // S2K-protected with this instance's GenerateKeyPair() password.
    int ExportSecretKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // Hex Key ID (8 bytes / 16 hex chars + null terminator) of this instance's own master key;
    // empty string before GenerateKeyPair() succeeds. outputBufferCapacity must be >= 17.
    int GetKeyId(char* outputBuffer, const int outputBufferCapacity) const override;

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
                         const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // ============================================================================================
    // Peer key (the other party's public key) -- unlike GenerateKeyPair() above, this instance
    // never generates or holds a peer's PRIVATE key. Import once before EncryptBuffer/
    // EncryptStringArmored (encrypts to the peer's encryption subkey) or VerifyBuffer/
    // VerifyClearSignedString (verifies against the peer's master key). keyBlockBuffer may be
    // either ASCII-armored ("-----BEGIN PGP PUBLIC KEY BLOCK-----") or raw binary packets --
    // detected automatically from the first bytes.
    // ============================================================================================

    int ImportPeerPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize) override;

    // Hex Key ID of the most recently imported peer master key; empty string before
    // ImportPeerPublicKey() succeeds.
    int GetPeerKeyId(char* outputBuffer, const int outputBufferCapacity) const override;

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
    int ImportAdditionalRecipientPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize) override;

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
                      const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Same as EncryptBuffer, ASCII-armored ("-----BEGIN PGP MESSAGE-----") text output instead of
    // raw binary.
    int EncryptStringArmored( const char* inputString, const int inputStringSize,
                             const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // GenerateKeyPair() must have succeeded first; password must match the one it was called
    // with. Decompresses ZIP/ZLIB/uncompressed literal bodies (whichever the sender used).
    int DecryptBuffer( const char* password, const int passwordSize,
                      const unsigned char* inputBuffer, const int inputBufferSize,
                      const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Same as DecryptBuffer, ASCII-armored input instead of raw binary.
    int DecryptStringArmored( const char* password, const int passwordSize,
                            const char* inputString, const int inputStringSize,
                            const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

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
                   const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // ImportPeerPublicKey() must have succeeded first. Returns NO_ERROR when verification
    // executed (isValid then reports whether the signature is cryptographically valid) or an
    // error code when verification could not run at all; *isValid is only meaningful when the
    // return value is NO_ERROR (same convention as CCryptoApi::VerifyBuffer).
    int VerifyBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                     const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid) override;

    // ============================================================================================
    // Clear-sign -- RFC 4880 section 7 framing ("-----BEGIN PGP SIGNED MESSAGE-----" / "Hash:
    // SHA256" / dash-escaped body / "-----BEGIN PGP SIGNATURE-----"), signature type 0x01
    // (canonical text document).
    // ============================================================================================

    // GenerateKeyPair() must have succeeded first; password must match the one it was called with.
    int ClearSignString( const char* password, const int passwordSize,
                        const char* inputString, const int inputStringSize,
                        const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // ImportPeerPublicKey() must have succeeded first. Same NO_ERROR/*isValid convention as
    // VerifyBuffer above.
    int VerifyClearSignedString(const char* clearSignedString, const int clearSignedStringSize, bool* isValid) override;

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
    // not something specific to this engine. RSA and Ed25519/X25519 identities may be mixed as
    // recipients. File signing and verification use RSA/SHA-256 or Ed25519/SHA-512 according to
    // the signing/peer identity's algorithm, while file encryption uses each recipient's own
    // RSA or X25519 encryption subkey.
    // ============================================================================================

    // ImportPeerPublicKey() must have succeeded first.
    int EncryptFile( const char* inputFilePath, const char* outputFilePath,
                    ProgressCallback onProgress, void* progressUserData) override;

    // Same as EncryptFile above (same recipients, same SEIP/MDC framing), except the plaintext is
    // wrapped in a Compressed Data packet (tag 8) using compressionAlgorithm instead of being
    // stored directly -- additive, EncryptFile itself is completely unaffected. Compressing a
    // stream whose length is not yet known cannot use EncryptFile's "compute every packet length
    // upfront" trick, so this method streams the plaintext into a temporary file first (named
    // outputFilePath with a ".pgpztmp" suffix, in the same directory; removed on every exit path --
    // success, any error, or OPERATION_CANCELLED), compressing it chunk-by-chunk as it is read so
    // peak memory never holds the whole file or the whole compressed result. Once that temporary
    // file's exact compressed size is known, this method writes the real PKESK + Compressed Data +
    // SEIP/MDC structure, streaming the temporary file's bytes in as the Compressed Data packet's
    // body (reusing the same SEIP/MDC streaming-write machinery EncryptFile itself uses). Because
    // of this two-pass design, onProgress is invoked across two separate passes over the data
    // (compress, then encrypt) rather than one continuous 0-100% sweep -- each pass reports
    // progress against its own total. ImportPeerPublicKey() must have succeeded first.
    int EncryptFileCompressed( const char* inputFilePath, const char* outputFilePath,
                             const PgpFileCompressionAlgorithm compressionAlgorithm,
                             ProgressCallback onProgress, void* progressUserData) override;

    // GenerateKeyPair() must have succeeded first; password must match the one it was called
    // with. Accepts an uncompressed literal packet such as EncryptFile produces, or a compressed
    // inner packet using uncompressed, ZIP, ZLIB, or BZip2 encoding (e.g. from EncryptFileCompressed,
    // EncryptBuffer, or GnuPG). New-format partial-body-length framing (RFC 4880 section 4.2.2.4) is
    // accepted on the outer Sym. Encrypted Integrity Protected Data packet and on the inner
    // Compressed/Literal Data packet alike, for all four compression encodings -- real GnuPG
    // switches to that framing for any message past its own output buffer size, so essentially
    // every gpg-encrypted file of more than a few KB arrives framed that way. The chunks are
    // consumed as the stream reaches them, so memory use stays constant as before (BZip2 keeps the
    // one buffering exception described above, which is unrelated to the framing).
    int DecryptFile( const char* password, const int passwordSize,
                    const char* inputFilePath, const char* outputFilePath,
                    ProgressCallback onProgress, void* progressUserData) override;

    // GenerateKeyPair() must have succeeded first; password must match the one it was called
    // with. signatureFilePath receives the raw (non-armored) detached signature packet, same
    // format SignBuffer produces.
    int SignFile( const char* password, const int passwordSize,
                 const char* inputFilePath, const char* signatureFilePath,
                 ProgressCallback onProgress, void* progressUserData) override;

    // ImportPeerPublicKey() must have succeeded first. Same NO_ERROR/*isValid convention as
    // VerifyBuffer above.
    int VerifyFile( const char* inputFilePath, const char* signatureFilePath,
                   bool* isValid, ProgressCallback onProgress, void* progressUserData) override;

    // ============================================================================================
    // Message inspection (read-only) -- answer structural questions about an OpenPGP message
    // WITHOUT decrypting or verifying it. None of these seven methods needs a key of any kind:
    // GenerateKeyPair/ImportPeerPublicKey need never have been called, they never touch this
    // instance's own state (all seven are const), and they never attempt a decryption or a
    // signature check, so they are safe to call on a message addressed to somebody else entirely.
    // They are pure RFC 4880 packet parsers over the bytes handed in.
    //
    // inputBuffer/inputBufferSize accept, auto-detected from the leading bytes exactly the way
    // ImportPeerPublicKey does: raw binary OpenPGP packets (e.g. EncryptBuffer/SignBuffer/
    // EncryptFile/SignFile output, or an armor-free gpg message), an ASCII-armored block
    // ("-----BEGIN PGP MESSAGE-----", "-----BEGIN PGP SIGNATURE-----", ...), or a clear-signed
    // message ("-----BEGIN PGP SIGNED MESSAGE-----", whose trailing signature block is the part
    // that gets parsed). New-format partial-body-length framing (RFC 4880 section 4.2.2.4) is
    // handled by the very same reassembly step DecryptFile/DecryptBuffer use, so a message real
    // GnuPG streamed out in chunks is inspected exactly like a definite-length one.
    //
    // WHAT CANNOT BE SEEN: for an ENCRYPTED message only the OUTER packet layer is visible --
    // which recipients it is addressed to (PKESK, tag 1), whether a passphrase can open it (SKESK,
    // tag 3), and whether the ciphertext is integrity protected (SEIP, tag 18, or AEAD, tag 20)
    // or not (SED, tag 9). The Compressed Data and Literal Data packets, and any signature packets
    // travelling with the plaintext, live INSIDE the ciphertext and are unreachable without the
    // decryption key -- no amount of parsing can change that. GetCompression therefore reports the
    // explicit PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION sentinel in that case rather than
    // guessing, and ListSigningKeyIds/ListSignatures report only the signatures they can actually
    // see (zero, for a message whose signatures are all inside the ciphertext). For an
    // UNENCRYPTED input -- a detached signature, a clear-signed message, a one-pass-signed and/or
    // compressed file -- everything is visible, including packets nested inside a Compressed Data
    // packet, which these methods decompress (uncompressed/ZIP/ZLIB/BZip2, the same four encodings
    // DecryptFile reads) purely to keep walking the packet tree.
    // ============================================================================================

    // *isPublicKeyEncrypted receives true when the message carries at least one Public-Key
    // Encrypted Session Key packet (PKESK, tag 1) -- i.e. it is addressed to one or more
    // recipient keys (see ListEncryptionKeyIds below for which ones). A message can legitimately
    // be both public-key and password encrypted at once (both PKESK and SKESK packets), so this
    // and IsPasswordEncrypted below are independent questions, not two halves of one.
    int IsPublicKeyEncrypted( const unsigned char* inputBuffer, const int inputBufferSize,
                             bool* isPublicKeyEncrypted) const override;

    // *isPasswordEncrypted receives true when the message carries a Symmetric-Key Encrypted
    // Session Key packet (SKESK, tag 3) -- i.e. a passphrase alone can open it. CPgpEngine itself
    // never PRODUCES such a message (it has no symmetric-only encryption method; CPgpEngineWrapper
    // does, via EncryptBufferSymmetric), but real gpg's "--symmetric" output is read correctly
    // here.
    int IsPasswordEncrypted( const unsigned char* inputBuffer, const int inputBufferSize,
                            bool* isPasswordEncrypted) const override;

    // *isIntegrityProtected receives true when the encrypted payload is wrapped in a Sym.
    // Encrypted Integrity Protected Data packet (SEIP, tag 18, the MDC-protected packet this
    // engine always writes) or in an AEAD Encrypted Data packet (tag 20, what recent GnuPG
    // releases produce for keys advertising AEAD support -- integrity protected by construction),
    // and false when it is the obsolete, unprotected Symmetrically Encrypted Data packet (SED,
    // tag 9). NOTE the honest edge case: false is ALSO what an input carrying no encrypted-data
    // packet at all (a detached signature, a clear-signed message, a plain compressed file) gets,
    // simply because there is no ciphertext there to protect -- call IsPublicKeyEncrypted/
    // IsPasswordEncrypted first if the two cases must be told apart.
    int IsIntegrityProtected( const unsigned char* inputBuffer, const int inputBufferSize,
                             bool* isIntegrityProtected) const override;

    // *compressionAlgorithm receives the RFC 4880 section 9.3 compression algorithm octet declared
    // by the first Compressed Data packet (tag 8) reachable WITHOUT decrypting (0 = uncompressed,
    // 1 = ZIP, 2 = ZLIB, 3 = BZip2), or one of the two PgpCompressionInspectionResult sentinels
    // documented above that enum: PGP_COMPRESSION_NOT_PRESENT (-1) when the input is not encrypted
    // and provably carries no Compressed Data packet, or
    // PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION (-2) when the input IS encrypted, so any compressed
    // layer would sit inside the ciphertext where it cannot be seen. Returns NO_ERROR in all three
    // cases (the answer is in the out-parameter, not the return code); INVALID_DATA only when the
    // input is not parseable as OpenPGP packets at all.
    int GetCompression( const unsigned char* inputBuffer, const int inputBufferSize,
                       int* compressionAlgorithm) const override;

    // Enumerates the Key ID of every PKESK packet -- the recipient keys the message is encrypted
    // to -- in the order they appear in the message, without decrypting anything. *keyIdCount
    // receives the number of records found (always set on success, even when zero), and the
    // caller's buffer receives that many fixed-stride PGP_INSPECTION_KEY_ID_RECORD_SIZE-byte
    // "XXXXXXXXXXXXXXXX\0" records back to back. Same capacity-query convention as
    // ExportPublicKeyArmored: outputBufferCapacity = 0 / outputBuffer = nullptr reports the
    // required byte count in *outputBufferSize and returns BUFFER_TOO_SMALL -- except when there
    // are no records at all, where *outputBufferSize = 0 and NO_ERROR is returned (there is
    // nothing a bigger buffer could hold). A recipient hidden with gpg's own "--throw-keyids"
    // legitimately reports an all-zero Key ID; that is the message's own content, not a parse
    // failure.
    int ListEncryptionKeyIds( const unsigned char* inputBuffer, const int inputBufferSize,
                             const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                             int* keyIdCount) const override;

    // Enumerates the issuer Key ID of every signature this parser can reach without decrypting --
    // Signature packets (tag 2, e.g. SignBuffer/SignFile detached signatures and the signature
    // block of a clear-signed message) and One-Pass Signature packets (tag 4, which real GnuPG
    // writes ahead of a signed-and-compressed document; this engine only READS them, it never
    // writes one). Same record layout, count semantics and BUFFER_TOO_SMALL convention as
    // ListEncryptionKeyIds above. A signature packet whose issuer cannot be determined (neither an
    // Issuer Key ID subpacket, type 16, nor an Issuer Fingerprint subpacket, type 33) is reported
    // as the 16-character record "????????????????" rather than being silently dropped, so the
    // count still matches ListSignatures below.
    int ListSigningKeyIds( const unsigned char* inputBuffer, const int inputBufferSize,
                          const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                          int* keyIdCount) const override;

    // Richer form of ListSigningKeyIds above, over exactly the same set of signature packets and
    // in the same order: each record is PGP_INSPECTION_SIGNATURE_RECORD_SIZE bytes of
    // "XXXXXXXXXXXXXXXX:TT:HH\0" -- the issuer Key ID (or "????????????????"), the RFC 4880
    // section 5.2.1 signature type octet as 2 hex chars (00 = binary document, 01 = canonical text
    // document, 10-13 = user-id certifications, 18 = subkey binding, 20 = key revocation, ...),
    // and the RFC 4880 section 9.4 hash algorithm octet as 2 hex chars (08 = SHA-256, 0A =
    // SHA-512, ...). Same count semantics and BUFFER_TOO_SMALL convention as the two methods
    // above. Version 3 and version 4 signature packets are reported; a signature packet of any
    // other version is skipped by BOTH this method and ListSigningKeyIds (consistently, so their
    // counts always agree), since its field layout is not one this parser claims to know.
    int ListSignatures( const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                       int* signatureCount) const override;

protected:

private:

    // CryptoPP types are kept out of this header so callers never need CryptoPP's own headers or
    // include path; only PgpEngine.cpp does (same pattern as CCryptoPPProvider).
    struct Impl;
    std::unique_ptr<Impl> impl_;

};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace CryptoApiNS

#endif

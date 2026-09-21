#ifndef AYCRYPTO_PGP_ENGINE_WRAPPER_H
#define AYCRYPTO_PGP_ENGINE_WRAPPER_H

#include "Definitions/Definitions.h"
#include "Interfaces/IPgpEngineWrapper.h"

#include <memory>

// DLL export/import boundary for CPgpEngineWrapper as a real C++ class -- same reasoning and same
// macro name as CryptoApi.h's/PgpEngine.h's own CRYPTOAPI_API (redefining it identically here is
// harmless: all three headers are commonly included in the same translation unit, and an identical
// macro redefinition is not an error).
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
// impl_ is private and never touched across the DLL boundary, and IPgpEngineWrapper (this class's
// base) declares no data and no non-inline code of its own.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4251)
#pragma warning(disable: 4275)
#endif

// ====================================================================================================
// CPgpEngineWrapper -- unlike CPgpEngine (which reimplements RFC 4880 itself on top of CryptoPP),
// this class does no cryptography of its own: every method shells out to a real, locally installed
// "gpg.exe" (GnuPG/Gpg4win) as a child process and lets it do the actual work. The public API below
// mirrors CPgpEngine's method-for-method (same names/signatures) so the two engines are drop-in
// interchangeable for the same call sites/tests, plus a handful of additional methods (marked below)
// that expose real gpg capabilities CPgpEngine's own v1 engine does not have (multi-recipient
// encryption, ECC/EdDSA keys).
//
// Each instance gets its OWN isolated --homedir (a fresh temporary directory created at construction
// time and removed at destruction time on a best-effort basis) -- the real user's default GnuPG
// keyring under %APPDATA%\gnupg is never touched. Buffer-suffixed methods (EncryptBuffer,
// SignBuffer, etc.) round-trip through temporary files under that same homedir, since gpg operates
// on files/stdio, not in-process buffers -- unlike CPgpEngine, which never touches disk for its own
// Buffer-suffixed methods. File-suffixed methods hand gpg the caller's paths directly.
//
// gpg.exe is located at runtime by probing the same well-known Gpg4win install paths the repo's own
// test helper (FindGpgExecutable in CryptoApiTester.cpp) already uses; this class reimplements that
// discovery independently since it is product code and must not depend on test-file internals.
// IsGnuPgAvailable() reports whether that discovery succeeded; every other method below returns
// NOT_IMPLEMENTED if it did not (no existing ErrorCode value means "external tool not found", and
// Rules.md's error-code guidance says to reuse an existing value rather than invent one).
//
// Child processes are spawned via CreateProcessW with fully redirected, non-inheritable stdio pipes
// (never through cmd.exe) -- this sidesteps cmd.exe's own command-line quote-stripping quirk
// entirely (irrelevant here since there is no shell in the middle) and also avoids the
// "agent_genkey failed: No such file or directory" failure the original design notes for this class
// worried about: that failure was reproduced during development and traced to gpg's homedir not
// existing as a directory yet (gpg creates its keyring/agent-socket files under --homedir on first
// use, but never creates the directory itself) -- this class always creates its homedir directory up
// front in the constructor, which was sufficient to avoid the issue in every scenario exercised by
// this class's own test suite (RunPgpWrapper*Test in CryptoApiTester.cpp/.h).
// ====================================================================================================

class CRYPTOAPI_API CPgpEngineWrapper : public IPgpEngineWrapper
{
public:
    virtual ~CPgpEngineWrapper();
             CPgpEngineWrapper();

    // rsaKeyBits selects the RSA key size the RSA-flavored GenerateKeyPair() overloads below will
    // pass to "gpg --batch --gen-key" (1024/2048/3072/4096); any other value is rejected by
    // GenerateKeyPair() with INVALID_ARGUMENT. Does not affect GenerateKeyPairEcc() below, which
    // always generates Ed25519/Cv25519 keys regardless of this constructor argument.
    explicit CPgpEngineWrapper(const int rsaKeyBits);

    // ============================================================================================
    // Availability -- safe to call before anything else (does not require GenerateKeyPair/
    // ImportPeerPublicKey to have run first). See the class comment above for what this reuses.
    // ============================================================================================

    bool IsGnuPgAvailable(void) const override;

    // ============================================================================================
    // Identity (own key pair) -- delegates to "gpg --batch --gen-key" with a generated parameter
    // file (RSA sign+certify master key, RSA encrypt-only subkey, exactly mirroring CPgpEngine's
    // own key-flag layout) inside this instance's isolated --homedir. password becomes that gpg
    // secret key's real S2K passphrase (gpg's own, not a value this class re-derives). Must be
    // called once (or GenerateKeyPairEcc below) before ExportPublicKeyArmored/ExportSecretKeyArmored/
    // DecryptBuffer/DecryptStringArmored/SignBuffer/ClearSignString; calling it again generates a
    // fresh gpg key in the same homedir, replacing the "current identity" this instance tracks (the
    // old key remains in gpg's keyring on disk but this instance no longer refers to it).
    // ============================================================================================

    int GenerateKeyPair( const char* userId, const int userIdSize,
                        const char* password, const int passwordSize) override;

    // Same as the 4-argument overload above, plus a real gpg key expiration date computed as "now +
    // expirationSeconds"; 0 means never expires (identical behavior to the 4-argument overload).
    int GenerateKeyPair( const char* userId, const int userIdSize,
                        const char* password, const int passwordSize,
                        const unsigned int expirationSeconds) override;

    // ============================================================================================
    // Extra capability beyond CPgpEngine: real ECC/EdDSA identities. Same contract as
    // GenerateKeyPair above (same "current identity" slot -- calling either family overwrites what
    // the other last set), except the master key is Ed25519 (sign+certify) and the encryption
    // subkey is Cv25519/ECDH, both natively supported by gpg's own "--batch --gen-key" parameter
    // file syntax (Key-Type: eddsa / Key-Curve: ed25519, Subkey-Type: ecdh / Subkey-Curve: cv25519).
    // CPgpEngine has no ECC support at all (RSA only), so there is no elliptic-curve analogue to
    // mirror there -- these two overloads exist only on this class.
    // ============================================================================================

    int GenerateKeyPairEcc( const char* userId, const int userIdSize,
                           const char* password, const int passwordSize) override;

    int GenerateKeyPairEcc( const char* userId, const int userIdSize,
                           const char* password, const int passwordSize,
                           const unsigned int expirationSeconds) override;

    // What the expirationSeconds argument was last called with, across GenerateKeyPair AND
    // GenerateKeyPairEcc (0 if neither has been called yet, or if a 4-argument overload -- always
    // "never expires" -- was used last).
    unsigned int GetKeyExpirationSeconds(void) const override;

    // Exact ASCII-armored size ExportPublicKeyArmored/ExportSecretKeyArmored would need; 0 before
    // GenerateKeyPair()/GenerateKeyPairEcc() succeeds. capacity=0/buffer=nullptr queries the
    // required size (see BUFFER_TOO_SMALL convention on the methods below).
    int GetPublicKeyArmoredSize(void) const override;
    int GetSecretKeyArmoredSize(void) const override;

    // "-----BEGIN PGP PUBLIC KEY BLOCK-----" as produced by "gpg --armor --export", captured once
    // right after key generation and cached (mirrors CPgpEngine's own ownPublicKeyArmored cache).
    int ExportPublicKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // "-----BEGIN PGP PRIVATE KEY BLOCK-----" as produced by "gpg --armor --export-secret-keys"
    // (captured once right after key generation, using the password GenerateKeyPair/
    // GenerateKeyPairEcc was called with, and cached -- same no-password-parameter contract as
    // CPgpEngine's own ExportSecretKeyArmored, for the same reason: the password was already
    // consumed once at generation/export time).
    int ExportSecretKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // Hex Key ID (8 bytes / 16 hex chars + null terminator) of this instance's own master key, as
    // reported by gpg itself; empty string before GenerateKeyPair()/GenerateKeyPairEcc() succeeds.
    // outputBufferCapacity must be >= 17.
    int GetKeyId(char* outputBuffer, const int outputBufferCapacity) const override;

    // GenerateKeyPair()/GenerateKeyPairEcc() must have succeeded first; password must match the one
    // it was called with. Delegates to "gpg --generate-revocation" (scripted via --command-fd/
    // --status-fd), armored under "-----BEGIN PGP PUBLIC KEY BLOCK-----" (gpg's own convention for
    // a standalone revocation certificate, same as CPgpEngine's own RevokeKeyArmored). reasonCode
    // uses the SAME RFC 4880 5.2.3.23 numbering CPgpEngine's own RevokeKeyArmored documents (0 = no
    // reason, 1 = key superseded, 2 = key compromised, 3 = key retired) -- internally translated to
    // gpg's own interactive menu order (0/1/2/3 = no reason/compromised/superseded/retired, verified
    // empirically against this machine's gpg.exe while building this class) so callers of either
    // engine pass the same reasonCode values for the same meaning. reasonText may be nullptr/
    // 0-length for no human-readable reason.
    int RevokeKeyArmored( const char* password, const int passwordSize,
                         const unsigned char reasonCode, const char* reasonText, const int reasonTextSize,
                         const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // ============================================================================================
    // Peer key(s) (the other party's public key) -- imported into this instance's own isolated gpg
    // keyring via "gpg --import". Unlike CPgpEngine (which tracks exactly one peer identity at a
    // time), this class keeps every successfully imported peer key id, in import order, so the
    // extra multi-recipient methods below can address any of them; GetPeerKeyId still mirrors
    // CPgpEngine's single-peer convention by reporting the MOST RECENTLY imported one.
    // ============================================================================================

    int ImportPeerPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize) override;

    // Hex Key ID of the most recently imported peer master key; empty string before
    // ImportPeerPublicKey() succeeds at least once.
    int GetPeerKeyId(char* outputBuffer, const int outputBufferCapacity) const override;

    // Extra capability beyond CPgpEngine: how many distinct peer keys ImportPeerPublicKey has
    // successfully imported into this instance's keyring so far (0 if none).
    int GetImportedPeerKeyCount(void) const override;

    // Extra capability beyond CPgpEngine: hex Key ID of the peerIndex-th imported peer key (0-based,
    // in import order); INVALID_ARGUMENT if peerIndex is out of range. outputBufferCapacity must be
    // >= 17.
    int GetImportedPeerKeyId(const int peerIndex, char* outputBuffer, const int outputBufferCapacity) const override;

    // ============================================================================================
    // Extra capability beyond CPgpEngine: ground-truth keyring introspection/removal, sourced
    // directly from real "gpg --with-colons --list-keys"/"--delete-key"/
    // "--delete-secret-and-public-key" -- unlike GetImportedPeerKeyCount/GetImportedPeerKeyId
    // above (which only report peer keys THIS instance itself imported through
    // ImportPeerPublicKey), these reflect whatever is actually in the underlying gpg keyring,
    // including keys this instance did not import itself.
    // ============================================================================================

    // Raw "gpg --with-colons --fingerprint --list-keys" output (every public key currently in this
    // instance's keyring -- own identity plus every imported peer, in gpg's own listing order),
    // same capacity-query/BUFFER_TOO_SMALL convention as ExportPublicKeyArmored above. Queried live
    // from gpg on every call (not cached, unlike ExportPublicKeyArmored), since DeletePeerPublicKey/
    // DeleteOwnIdentity below can change the keyring after construction. The combined stdout/stderr
    // capture this class's subprocess helper uses (see PgpEngineWrapper.cpp) means occasional
    // diagnostic lines from gpg itself (e.g. "gpg: checking the trustdb") may be interleaved with
    // the colon-format records; callers parsing this text should key off the documented
    // "pub:"/"fpr:"/etc. line prefixes, same as this class's own internal parsing does, and ignore
    // anything else.
    int GetKeyringListing(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const override;

    // How many distinct public keys "gpg --with-colons --list-keys" currently reports (own identity
    // plus every imported peer) -- ground truth, unlike GetImportedPeerKeyCount above. 0 if none or
    // if gpg could not be queried.
    int GetKeyringKeyCount(void) const override;

    // Hex Key ID (16 hex chars) of the keyIndex-th public key (0-based, in gpg's own listing order)
    // currently in the keyring; INVALID_ARGUMENT if keyIndex is out of range. outputBufferCapacity
    // must be >= 17.
    int GetKeyringKeyId(const int keyIndex, char* outputBuffer, const int outputBufferCapacity) const override;

    // Removes one specific imported peer public key from the real keyring (real
    // "gpg --delete-key <id>"); keyId should be a hex Key ID GetImportedPeerKeyId or
    // GetKeyringKeyId has reported (this instance's own key id is rejected with INVALID_ARGUMENT --
    // use DeleteOwnIdentity below for that). Also removes it from this instance's own
    // peer-tracking list if present there, so GetImportedPeerKeyCount/GetImportedPeerKeyId reflect
    // the keyring again afterward.
    int DeletePeerPublicKey(const char* keyId, const int keyIdSize) override;

    // Removes THIS instance's own identity (secret AND public key) from the real keyring (real
    // "gpg --delete-secret-and-public-key", scripted with the full fingerprint gpg's own batch
    // mode requires for this operation rather than the short Key ID -- verified against this
    // machine's gpg.exe while building this feature, which otherwise refuses with "can't do this
    // in batch mode"). GenerateKeyPair()/GenerateKeyPairEcc() must have succeeded first. Resets
    // this instance's own "current identity" state as if neither had ever been called: GetKeyId
    // returns an empty string, ExportPublicKeyArmored/ExportSecretKeyArmored report size 0,
    // GetKeyExpirationSeconds returns 0, and GenerateKeyPair/GenerateKeyPairEcc may be called again
    // afterward to create a fresh identity in the same homedir.
    int DeleteOwnIdentity(void) override;

    // ============================================================================================
    // Encrypt (to the imported peer's key) / Decrypt (with this instance's own secret key) --
    // delegates to "gpg --encrypt"/"gpg --decrypt" through a temporary input/output file pair under
    // this instance's homedir (removed afterwards on a best-effort basis).
    // ============================================================================================

    // ImportPeerPublicKey() must have succeeded first (encrypts to the MOST RECENTLY imported peer,
    // same single-recipient convention as CPgpEngine's own EncryptBuffer -- see
    // EncryptBufferMultiRecipient below for more than one recipient at once).
    int EncryptBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                      const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Same as EncryptBuffer, plus an explicit PgpCompressionAlgorithm override (real gpg's own
    // "--compress-algo") instead of gpg's own default. See the PgpCompressionAlgorithm comment
    // above this class for the exact values/algorithms; INVALID_ARGUMENT if compressionAlgorithm
    // is not one of them.
    int EncryptBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                      const PgpCompressionAlgorithm compressionAlgorithm,
                      const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Same as EncryptBuffer, ASCII-armored ("-----BEGIN PGP MESSAGE-----") text output instead of
    // raw binary (gpg's own "--armor --encrypt").
    int EncryptStringArmored( const char* inputString, const int inputStringSize,
                             const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // Same as EncryptStringArmored, plus an explicit PgpCompressionAlgorithm override -- same
    // contract as the EncryptBuffer overload above.
    int EncryptStringArmored( const char* inputString, const int inputStringSize,
                             const PgpCompressionAlgorithm compressionAlgorithm,
                             const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // ============================================================================================
    // Extra capability beyond CPgpEngine: symmetric-only ("passphrase") encryption -- no recipient
    // key and no identity of any kind required from the encrypting party (GenerateKeyPair/
    // GenerateKeyPairEcc need never be called on this instance at all). Delegates to real gpg's own
    // "--symmetric" ("gpg -c"), which produces a Symmetric-Key Encrypted Session Key (SKESK, RFC
    // 4880 5.3) packet instead of a Public-Key Encrypted Session Key (PKESK) one. No new DECRYPT
    // method is needed for this: DecryptBuffer/DecryptStringArmored below already delegate to plain
    // "gpg --decrypt --passphrase-fd 0", and real gpg's own --decrypt autodetects SKESK vs. PKESK
    // from the ciphertext itself and reads a passphrase off passphrase-fd either way -- verified
    // directly against this machine's gpg.exe while adding this feature, decrypting a
    // --symmetric-produced message with a freshly constructed CPgpEngineWrapper that had NEVER
    // called GenerateKeyPair/GenerateKeyPairEcc. The only change this feature required on the
    // decrypt side was removing this class's own internal precondition that used to unconditionally
    // require an own identity before even attempting "gpg --decrypt" (irrelevant, and wrong, for a
    // passphrase-only message) -- see DecryptBuffer/DecryptStringArmored's own comments below.
    // ============================================================================================

    // passphrase/passphraseSize is UTF-8 text (same convention as every other password/passphrase
    // parameter in this class), fed to gpg over passphrase-fd exactly like DecryptBuffer's password
    // parameter; it is gpg's own real S2K passphrase for this one message; nothing is cached or
    // reused across calls.
    int EncryptBufferSymmetric( const char* passphrase, const int passphraseSize,
                               const unsigned char* inputBuffer, const int inputBufferSize,
                               const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Same as EncryptBufferSymmetric, ASCII-armored text output instead of raw binary (gpg's own
    // "--armor --symmetric").
    int EncryptStringArmoredSymmetric( const char* passphrase, const int passphraseSize,
                                      const char* inputString, const int inputStringSize,
                                      const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // ============================================================================================
    // Extra capability beyond CPgpEngine: real multi-recipient encryption -- one shared session key,
    // one ciphertext, decryptable by ANY of the listed recipients' own secret key (real gpg "-r
    // <id1> -r <id2> ... --encrypt", not N independent single-recipient ciphertexts). Every id in
    // recipientKeyIds must be a key id ImportPeerPublicKey has already imported into this instance
    // (see GetImportedPeerKeyCount/GetImportedPeerKeyId above to enumerate them).
    // ============================================================================================

    int EncryptBufferMultiRecipient( const unsigned char* inputBuffer, const int inputBufferSize,
                                    const char* const* recipientKeyIds, const int recipientCount,
                                    const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Same as EncryptBufferMultiRecipient, plus an explicit PgpCompressionAlgorithm override -- same
    // contract as the EncryptBuffer compression overload above.
    int EncryptBufferMultiRecipient( const unsigned char* inputBuffer, const int inputBufferSize,
                                    const char* const* recipientKeyIds, const int recipientCount,
                                    const PgpCompressionAlgorithm compressionAlgorithm,
                                    const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Same as EncryptBufferMultiRecipient, ASCII-armored text output instead of raw binary.
    int EncryptStringArmoredMultiRecipient( const char* inputString, const int inputStringSize,
                                           const char* const* recipientKeyIds, const int recipientCount,
                                           const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // Same as EncryptStringArmoredMultiRecipient, plus an explicit PgpCompressionAlgorithm
    // override -- same contract as the EncryptBuffer compression overload above.
    int EncryptStringArmoredMultiRecipient( const char* inputString, const int inputStringSize,
                                           const char* const* recipientKeyIds, const int recipientCount,
                                           const PgpCompressionAlgorithm compressionAlgorithm,
                                           const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // GenerateKeyPair()/GenerateKeyPairEcc() must have succeeded first for a public-key-encrypted
    // (PKESK) message; password must match the one it was called with. Delegates to "gpg --decrypt";
    // decompresses whatever compression (if any) the sender used, since real gpg handles that
    // transparently. UNLIKE every other method in this section, an own identity is NOT actually
    // required to decrypt a message produced by EncryptBufferSymmetric/EncryptStringArmoredSymmetric
    // above (a Symmetric-Key Encrypted Session Key/SKESK message) -- real gpg's own --decrypt
    // autodetects SKESK vs. PKESK from the ciphertext and reads the passphrase off passphrase-fd
    // either way, so this method works unmodified for both cases; password is then that message's
    // real passphrase rather than an identity's key password. Verified directly against this
    // machine's gpg.exe while adding symmetric-encryption support to this class.
    int DecryptBuffer( const char* password, const int passwordSize,
                      const unsigned char* inputBuffer, const int inputBufferSize,
                      const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Same as DecryptBuffer (including the symmetric/SKESK note above), ASCII-armored input instead
    // of raw binary.
    int DecryptStringArmored( const char* password, const int passwordSize,
                            const char* inputString, const int inputStringSize,
                            const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // ============================================================================================
    // Sign (with this instance's own key) / Verify (against an imported peer's key) -- delegates to
    // "gpg --detach-sign" / "gpg --verify" through temporary files.
    // ============================================================================================

    // GenerateKeyPair()/GenerateKeyPairEcc() must have succeeded first; password must match the one
    // it was called with.
    int SignBuffer( const char* password, const int passwordSize,
                   const unsigned char* inputBuffer, const int inputBufferSize,
                   const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // ImportPeerPublicKey() must have succeeded first. Returns NO_ERROR when "gpg --verify" ran
    // (isValid then reports whether it reported a good signature) or an error code when it could
    // not run at all; *isValid is only meaningful when the return value is NO_ERROR (same
    // convention as CCryptoApi::VerifyBuffer and CPgpEngine::VerifyBuffer).
    int VerifyBuffer( const unsigned char* inputBuffer, const int inputBufferSize,
                     const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid) override;

    // ============================================================================================
    // Clear-sign -- delegates to "gpg --clear-sign" / "gpg --verify".
    // ============================================================================================

    // GenerateKeyPair()/GenerateKeyPairEcc() must have succeeded first; password must match the one
    // it was called with.
    int ClearSignString( const char* password, const int passwordSize,
                        const char* inputString, const int inputStringSize,
                        const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) override;

    // ImportPeerPublicKey() must have succeeded first. Same NO_ERROR/*isValid convention as
    // VerifyBuffer above.
    int VerifyClearSignedString(const char* clearSignedString, const int clearSignedStringSize, bool* isValid) override;

    // ============================================================================================
    // File-based variants -- unlike CPgpEngine's own streaming chunked implementation (needed there
    // because the engine itself has to bound its memory use), these simply hand the caller's file
    // paths straight to gpg, which does its own I/O; onProgress is invoked once with 0% immediately
    // before the gpg process is started (returning false there aborts with OPERATION_CANCELLED
    // before gpg even runs) and once with 100% after it exits successfully -- real gpg's CLI does
    // not expose fine-grained byte-level progress the way CPgpEngine's own chunk loop does, so this
    // is a deliberately coarser (but still real and honest) progress contract, documented here
    // rather than pretending to a granularity this backend cannot provide.
    // ============================================================================================

    // ImportPeerPublicKey() must have succeeded first (encrypts to the most recently imported peer,
    // same convention as EncryptBuffer).
    int EncryptFile( const char* inputFilePath, const char* outputFilePath,
                    ProgressCallback onProgress, void* progressUserData) override;

    // GenerateKeyPair()/GenerateKeyPairEcc() must have succeeded first; password must match the one
    // it was called with.
    int DecryptFile( const char* password, const int passwordSize,
                    const char* inputFilePath, const char* outputFilePath,
                    ProgressCallback onProgress, void* progressUserData) override;

    // GenerateKeyPair()/GenerateKeyPairEcc() must have succeeded first; password must match the one
    // it was called with. signatureFilePath receives gpg's raw (non-armored) detached signature.
    int SignFile( const char* password, const int passwordSize,
                 const char* inputFilePath, const char* signatureFilePath,
                 ProgressCallback onProgress, void* progressUserData) override;

    // ImportPeerPublicKey() must have succeeded first. Same NO_ERROR/*isValid convention as
    // VerifyBuffer above.
    int VerifyFile( const char* inputFilePath, const char* signatureFilePath,
                   bool* isValid, ProgressCallback onProgress, void* progressUserData) override;

    // ============================================================================================
    // Message inspection (read-only) -- the gpg-backed mirror of CPgpEngine's own seven inspection
    // methods (same names, same signatures, same out-parameter meanings and the same record
    // layout, so the two engines stay drop-in interchangeable for inspection too). Where
    // CPgpEngine parses the packets itself, these delegate to real "gpg --list-packets" against a
    // temporary file holding the input under this instance's own isolated homedir, and parse gpg's
    // own listing text -- the same "let the real tool be the authority, then parse its output"
    // approach GetKeyringListing/GetKeyringKeyCount take with "--with-colons".
    //
    // "--pinentry-mode cancel" is always passed alongside --list-packets, which is what makes the
    // read-only promise real rather than aspirational: gpg would otherwise try to open an
    // encrypted input it holds a key for, blocking on a passphrase prompt (observed taking a full
    // agent timeout before failing) and, for a passphrase-less secret key, actually decrypting and
    // then listing the INNER packets too. With the prompt refused up front, a
    // passphrase-protected message is listed strictly from its outer packet layer, fast, and
    // nothing is ever decrypted. The one honest exception, unavoidable with a real gpg backend: if
    // the keyring happens to hold an UNPROTECTED (no-passphrase) secret key matching the message,
    // gpg needs no prompt and will report the inner packets as well -- which only ever makes
    // GetCompression/ListSignatures below MORE informative than the contract promises, never less.
    //
    // Everything CPgpEngine's own inspection section documents about what cannot be seen without
    // decrypting applies here unchanged, for the same structural reasons.
    //
    // inputBuffer/inputBufferSize accept raw binary OpenPGP packets, an ASCII-armored block (gpg
    // dearmors it itself), or a clear-signed message -- for which this class extracts the trailing
    // "-----BEGIN PGP SIGNATURE-----" block and lists THAT, because gpg's own --list-packets, fed
    // a whole clear-signed message, reports only its literal-text framing and never mentions the
    // signature packet at all (verified against GnuPG 2.5.21 while building these methods).
    // ============================================================================================

    // *isPublicKeyEncrypted receives true when gpg reports at least one Public-Key Encrypted
    // Session Key packet (tag 1). Same contract as CPgpEngine::IsPublicKeyEncrypted.
    int IsPublicKeyEncrypted( const unsigned char* inputBuffer, const int inputBufferSize,
                             bool* isPublicKeyEncrypted) const override;

    // *isPasswordEncrypted receives true when gpg reports a Symmetric-Key Encrypted Session Key
    // packet (tag 3) -- i.e. what EncryptBufferSymmetric/EncryptStringArmoredSymmetric above
    // produce. Same contract as CPgpEngine::IsPasswordEncrypted.
    int IsPasswordEncrypted( const unsigned char* inputBuffer, const int inputBufferSize,
                            bool* isPasswordEncrypted) const override;

    // *isIntegrityProtected receives true for a Sym. Encrypted Integrity Protected Data packet
    // (tag 18) or an AEAD Encrypted Data packet (tag 20) -- note recent GnuPG (2.5.x, this
    // machine's) writes tag 20 by default whenever every recipient key advertises AEAD support, so
    // that is the packet this class's own EncryptBuffer output normally carries -- and false for
    // the obsolete unprotected Symmetrically Encrypted Data packet (tag 9). Carries the same
    // "false also means no encrypted-data packet at all" caveat CPgpEngine::IsIntegrityProtected
    // documents.
    int IsIntegrityProtected( const unsigned char* inputBuffer, const int inputBufferSize,
                             bool* isIntegrityProtected) const override;

    // *compressionAlgorithm receives the RFC 4880 section 9.3 compression algorithm octet of the
    // first Compressed Data packet gpg reports (0 = uncompressed, 1 = ZIP, 2 = ZLIB, 3 = BZIP2 --
    // the same numbering PgpCompressionAlgorithm at the top of this header uses), or one of the
    // two NEGATIVE sentinels CPgpEngine's own PgpCompressionInspectionResult enum names, with
    // identical values and meanings: -1 when the input is not encrypted and provably carries no
    // Compressed Data packet, -2 when the input IS encrypted so any compressed layer sits
    // unreachable inside the ciphertext. (The enum itself is deliberately not redeclared here --
    // both headers live in the same namespace and are routinely included together, so a second
    // declaration of the same names would collide; include PgpEngine.h to use the named constants
    // or compare against the literals.) Returns NO_ERROR in all three cases; INVALID_DATA only
    // when gpg could not make sense of the input as OpenPGP packets at all.
    int GetCompression( const unsigned char* inputBuffer, const int inputBufferSize,
                       int* compressionAlgorithm) const override;

    // Enumerates the recipient Key ID of every PKESK packet gpg reports, in listing order.
    // *keyIdCount receives the number of records (always set on success, even when zero) and the
    // caller's buffer receives that many packed, fixed-stride 17-byte "XXXXXXXXXXXXXXXX\0" records
    // -- byte-for-byte the same layout CPgpEngine::ListEncryptionKeyIds produces (its
    // PGP_INSPECTION_KEY_ID_RECORD_SIZE). Same capacity-query/BUFFER_TOO_SMALL convention as
    // GetKeyringListing above, with the same refinement CPgpEngine documents: an EMPTY list is
    // NO_ERROR with *outputBufferSize = 0, not BUFFER_TOO_SMALL.
    int ListEncryptionKeyIds( const unsigned char* inputBuffer, const int inputBufferSize,
                             const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                             int* keyIdCount) const override;

    // Enumerates the issuer Key ID of every Signature (tag 2) and One-Pass Signature (tag 4)
    // packet gpg reports, in listing order -- covering detached signatures (SignBuffer/SignFile
    // output), the signature block of a clear-signed message, and the one-pass signature real gpg
    // writes ahead of a signed document. Same 17-byte record layout and count/BUFFER_TOO_SMALL
    // semantics as ListEncryptionKeyIds above; an issuer gpg does not name is reported as
    // "????????????????", exactly as CPgpEngine::ListSigningKeyIds does.
    int ListSigningKeyIds( const unsigned char* inputBuffer, const int inputBufferSize,
                          const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                          int* keyIdCount) const override;

    // Richer form of ListSigningKeyIds above, over the same signature packets in the same order:
    // each record is 23 bytes of "XXXXXXXXXXXXXXXX:TT:HH\0" -- issuer Key ID, RFC 4880 section
    // 5.2.1 signature type octet as 2 hex chars (gpg's own "sigclass"), and section 9.4 hash
    // algorithm octet as 2 hex chars (gpg's own "digest algo") -- byte-for-byte the layout
    // CPgpEngine::ListSignatures produces (its PGP_INSPECTION_SIGNATURE_RECORD_SIZE). Same
    // count/BUFFER_TOO_SMALL semantics as the two methods above.
    int ListSignatures( const unsigned char* inputBuffer, const int inputBufferSize,
                       const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize,
                       int* signatureCount) const override;

protected:

private:

    // Windows/subprocess/gpg-CLI details are kept out of this header so callers never need
    // Windows.h or any gpg-specific include path; only PgpEngineWrapper.cpp does.
    struct Impl;
    std::unique_ptr<Impl> impl_;

};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace CryptoApiNS

#endif

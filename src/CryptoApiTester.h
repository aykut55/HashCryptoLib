#ifndef CRYPTOAPI_CRYPTO_API_TESTER_H
#define CRYPTOAPI_CRYPTO_API_TESTER_H

namespace CryptoApiNS
{

class CCryptoApiTester
{
public:
    virtual ~CCryptoApiTester();
             CCryptoApiTester();

    int Run(void);

    int RunEncryptDecryptFileTest(void);

    int RunEncryptDecryptStringTest(void);

    int RunEncryptDecryptBufferTest(void);

    int RunEncryptDecryptBytesTest(void);

    // Hash-only analogues of RunEncryptDecryptFileTest/StringTest/BufferTest/BytesTest: no
    // password, no ciphertext, no Decrypt* counterpart (hashing is one-way) -- construct
    // CCryptoApi via the no-arg constructor (defaults to HASH_SHA256) and round-trip a known
    // payload through ComputeHashFile/String/Buffer/Bytes, verifying every shape agrees on the
    // same digest for the same content.
    int RunHashFileTest(void);

    int RunHashStringTest(void);

    int RunHashBufferTest(void);

    int RunHashBytesTest(void);

    // Variants of RunEncryptDecryptFileTest/StringTest/BufferTest/BytesTest that construct
    // CCryptoApi via CCryptoApi(const ProviderKind, const AeadAlgorithm) instead of the no-arg
    // constructor (which defaults to PROVIDER_MICROSOFT/AEAD_AES_256_GCM), so each one proves the
    // constructor-selected provider/algorithm is actually threaded through CCryptoApi's password
    // KDF + chunked encrypt/decrypt path end to end, not just the raw Factory/IAeadCipher path
    // RunProviderFactoryTest already covers. One full, independent method per provider/type pair
    // (no shared helper) so a failure names its own provider and payload shape directly.
    int RunMicrosoftProviderEncryptDecryptFileTest(void);

    int RunMicrosoftProviderEncryptDecryptStringTest(void);

    int RunMicrosoftProviderEncryptDecryptBufferTest(void);

    int RunMicrosoftProviderEncryptDecryptBytesTest(void);

    int RunCryptoPPProviderEncryptDecryptFileTest(void);

    int RunCryptoPPProviderEncryptDecryptStringTest(void);

    int RunCryptoPPProviderEncryptDecryptBufferTest(void);

    int RunCryptoPPProviderEncryptDecryptBytesTest(void);

    int RunBotanProviderEncryptDecryptFileTest(void);

    int RunBotanProviderEncryptDecryptStringTest(void);

    int RunBotanProviderEncryptDecryptBufferTest(void);

    int RunBotanProviderEncryptDecryptBytesTest(void);

    int RunOpenSslProviderEncryptDecryptFileTest(void);

    int RunOpenSslProviderEncryptDecryptStringTest(void);

    int RunOpenSslProviderEncryptDecryptBufferTest(void);

    int RunOpenSslProviderEncryptDecryptBytesTest(void);

    // Exercises CCryptoApi's RSA surface (GenerateAsymmetricKeyPair/EncryptWithPublicKey/
    // DecryptWithPrivateKey/GetMaxAsymmetricPlaintextSize/GetAsymmetricCiphertextSize) via the
    // 3-argument constructor, one full independent method per provider (no shared helper).
    int RunMicrosoftProviderAsymmetricTest(void);

    int RunCryptoPPProviderAsymmetricTest(void);

    int RunBotanProviderAsymmetricTest(void);

    int RunOpenSslProviderAsymmetricTest(void);

    // Exercises CCryptoApi's Legacy+MAC surface (EncryptLegacyBuffer/DecryptLegacyBuffer, LEGACY_
    // AES_256_CBC via the 4-argument constructor) -- round-trip, wrong password, tampered
    // ciphertext and tampered MAC tag must all fail closed. One full independent method per
    // provider (no shared helper).
    int RunMicrosoftProviderLegacyTest(void);

    int RunCryptoPPProviderLegacyTest(void);

    int RunBotanProviderLegacyTest(void);

    int RunOpenSslProviderLegacyTest(void);

    // Breadth companion to RunMicrosoftProviderLegacyTest/CryptoPP/Botan/OpenSsl (which each cover
    // one algorithm, LEGACY_AES_256_CBC, in depth including tamper rejection): this one loops over
    // every ProviderKind x every LegacySymmetricAlgorithm value (the same providerCases[] pattern
    // as RunProviderFactoryTest) via CCryptoApi's 4-argument constructor + EncryptLegacyBuffer/
    // DecryptLegacyBuffer, cross-checked against ICryptoProviderFactory::SupportsLegacyAlgorithm()
    // as ground truth -- supported combinations must round-trip, unsupported ones must be cleanly
    // rejected. Nothing here is hardcoded to "CBC only"; whatever each provider actually supports
    // gets exercised through the facade, not just the raw Factory.
    int RunLegacyAlgorithmsTest(void);

    // Demo (not an exhaustive breadth test -- see RunLegacyAlgorithmsTest for that) showing
    // CCryptoApi's AES "richness" (key size x mode) entirely in memory over UTF-8 text, inspired
    // by the online AES tool survey in AesOnlineToolsResearch.md. Single-provider (CryptoPP: fast
    // PBKDF2 + widest native AES mode range) so it runs quickly. AEAD combos (GCM/CCM/EAX/SIV/
    // GCM-SIV x 128/192/256) go through EncryptString/DecryptString; Legacy combos (CBC/CTR/CFB/
    // OFB/ECB x 128/192/256) go through EncryptLegacyBuffer/DecryptLegacyBuffer with the UTF-8
    // text treated as a raw byte buffer, since CCryptoApi has no EncryptLegacyString.
    int RunAesConfigurationDemoTest(void);

    // Exercises CUtils::HexEncode/HexDecode/Base64Encode/Base64Decode (src/Utils/Utils.h): known
    // test vectors (including the classic "Man"/"Ma"/"M" Base64 padding cases and a byte with
    // A-F hex digits to catch upper/lower-case mistakes), empty input, the BUFFER_TOO_SMALL
    // capacity-query convention, and malformed-input rejection (odd-length hex, non-hex/non-
    // base64 characters, wrong padding).
    int RunEncodingUtilsTest(void);

    // Exercises CUtils::Pad/Unpad (src/Utils/Utils.h) for all 7 PaddingScheme values: round-trip
    // over inputs both aligned to and misaligned from a 16-byte (AES) block size, known PKCS7
    // vectors, PADDING_NONE's alignment requirement, and Unpad's rejection of malformed padding
    // (bad pad-length byte, inconsistent pad bytes, wrong ISO97971 marker).
    int RunPaddingUtilsTest(void);

    // Demonstrates the two-step composition pattern for text output encoding: CCryptoApi's
    // Encrypt*/Decrypt* always move raw bytes, so a caller wanting Hex or Base64 text chains a
    // CUtils encode/decode step on top (Encrypt -> HexEncode/Base64Encode; Base64Decode/HexDecode
    // -> Decrypt). No new API surface on CCryptoApi itself -- see the aes_richness_design_track
    // memory entry recording this as the resolved design.
    int RunEncryptHexBase64CompositionTest(void);

    // File-based analogue of RunEncryptHexBase64CompositionTest: EncryptFile always writes raw
    // ciphertext bytes to disk, so getting a Hex/Base64 *text* file means reading that binary file
    // back into memory, running it through CUtils::HexEncode/Base64Encode, and writing the result
    // as its own text file -- then reversing the same steps (read text file -> HexDecode/
    // Base64Decode -> write binary file -> DecryptFile) to recover the original.
    int RunEncryptFileHexBase64CompositionTest(void);

    // Hash analogue of RunEncryptHexBase64CompositionTest/RunEncryptFileHexBase64CompositionTest:
    // a digest is just raw bytes like ciphertext is, so the same CUtils::HexEncode/Base64Encode
    // (and decode-back) composition applies -- ComputeHash* -> HexEncode/Base64Encode -> HexDecode/
    // Base64Decode -> compare against the original digest bytes. In-memory and file-based variants.
    int RunHashHexBase64CompositionTest(void);

    int RunHashFileHexBase64CompositionTest(void);

    // Exercises CCryptoApi's Hash surface (GetHashSize/ComputeHashBuffer/ComputeHashString/
    // ComputeHashFile via the 5-argument constructor, HASH_SHA256) -- known FIPS 180-4 test
    // vectors (empty string and "abc"), cross-checks that Buffer/String/File all produce the same
    // digest for equivalent content, and confirms GetHashSize() matches the actual output size.
    // One full independent method per provider (no shared helper).
    int RunMicrosoftProviderHashTest(void);

    int RunCryptoPPProviderHashTest(void);

    int RunBotanProviderHashTest(void);

    int RunOpenSslProviderHashTest(void);

    // Breadth companion to the 4 Run<Vendor>ProviderHashTest methods (which each cover HASH_SHA256
    // in depth): loops every ProviderKind x every HashAlgorithm value via CCryptoApi's 5-argument
    // constructor + ComputeHashBuffer, cross-checked against
    // ICryptoProviderFactory::SupportsHashAlgorithm() as ground truth -- supported combinations
    // must produce a digest matching GetHashSize(), unsupported ones must be cleanly rejected.
    int RunHashAlgorithmsTest(void);

    // Exercises CCryptoApi's Signature surface (GenerateSignatureKeyPair/GetSignatureSize/
    // SignBuffer/VerifyBuffer via the 6-argument or Signature-only 2-argument constructor) --
    // sign+verify round-trip, tampered-message rejection, and tampered-signature rejection. Each
    // method exercises a different SignatureAlgorithm for coverage diversity (breadth of all 5
    // values x all 4 providers is RunSignatureAlgorithmsTest's job, not this one's): Microsoft/
    // OpenSSL use ECDSA-P256 (supported everywhere), CryptoPP uses RSA-PSS-2048, Botan uses
    // Ed25519. One full independent method per provider (no shared helper).
    int RunMicrosoftProviderSignatureTest(void);

    int RunCryptoPPProviderSignatureTest(void);

    int RunBotanProviderSignatureTest(void);

    int RunOpenSslProviderSignatureTest(void);

    // Breadth companion to the 4 Run<Vendor>ProviderSignatureTest methods: loops every
    // ProviderKind x every SignatureAlgorithm value via CCryptoApi's Signature-only 2-argument
    // constructor + GenerateSignatureKeyPair/SignBuffer/VerifyBuffer, cross-checked against
    // ICryptoProviderFactory::SupportsSignatureAlgorithm() as ground truth -- supported
    // combinations must round-trip, unsupported ones (e.g. SIGNATURE_ED25519 on Microsoft, see
    // the "honest unsupported" note on CMicrosoftProvider's SignatureAlgorithmName) must be
    // cleanly rejected.
    int RunSignatureAlgorithmsTest(void);

    // Exercises CCryptoApi's Key agreement surface (GenerateKeyAgreementKeyPair/
    // GetKeyAgreementPublicKeySize/GetSharedSecretSize/ExportKeyAgreementPublicKey/
    // DeriveSharedSecret via the 7-argument or Key-agreement-only 2-argument constructor).
    // Unlike Signature/RSA above (self-contained round trip inside one CCryptoApi instance), key
    // agreement is inherently two-party: each method creates TWO independent CCryptoApi instances
    // ("alice"/"bob") of the same provider+algorithm, has each generate its own key pair, exchanges
    // exported public keys, and asserts both sides derive a byte-identical shared secret -- plus
    // that substituting a tampered peer public key does not silently reproduce the same secret.
    // Each method exercises a different KeyAgreementAlgorithm for coverage diversity (breadth of
    // both values x all 4 providers is RunKeyAgreementAlgorithmsTest's job, not this one's):
    // Microsoft/CryptoPP use ECDH-P256 (Microsoft's only supported value -- see
    // ccryptoapi_factory_unification_goal memory on CNG's lack of standard X25519), Botan/OpenSSL
    // use X25519. One full independent method per provider (no shared helper).
    int RunMicrosoftProviderKeyAgreementTest(void);

    int RunCryptoPPProviderKeyAgreementTest(void);

    int RunBotanProviderKeyAgreementTest(void);

    int RunOpenSslProviderKeyAgreementTest(void);

    // Breadth companion to the 4 Run<Vendor>ProviderKeyAgreementTest methods: loops every
    // ProviderKind x every KeyAgreementAlgorithm value, each iteration creating a fresh alice/bob
    // pair via CCryptoApi's Key-agreement-only 2-argument constructor +
    // GenerateKeyAgreementKeyPair/ExportKeyAgreementPublicKey/DeriveSharedSecret, cross-checked
    // against ICryptoProviderFactory::SupportsKeyAgreementAlgorithm() as ground truth -- supported
    // combinations must agree on a shared secret, unsupported ones (KEYAGREEMENT_X25519 on
    // Microsoft) must be cleanly rejected.
    int RunKeyAgreementAlgorithmsTest(void);

    // Full AES parameter matrix: 13 AEAD (GCM/CCM/EAX/SIV/GCM-SIV x supported key sizes) + 15
    // Legacy (CBC/CTR/CFB/OFB/ECB x 128/192/256) = 28 algorithm/mode/key-size combinations, x 4
    // providers = 112 literal blocks. Deliberately written WITHOUT a for/while loop over the
    // algorithm lists (unlike RunSignatureAlgorithmsTest/RunKeyAgreementAlgorithmsTest above) --
    // user explicitly asked to see each combination's CCryptoApi constructor argument spelled out
    // on its own, not abstracted into a cases[] loop. Each block round-trips (or, for a provider
    // lacking that mode, asserts correctly-unsupported) via EncryptBuffer/DecryptBuffer (AEAD) or
    // EncryptLegacyBuffer/DecryptLegacyBuffer (Legacy). Support/non-support per block is taken
    // directly from each C*Provider.cpp's own AeadAlgorithmName/LegacyAlgorithmName switch.
    int RunAESTests(void);

    // Exercises CCryptoApi::GetShared()'s Multiton cache: same-config calls must return the exact
    // same instance (identity, not just equal state), different-config calls must return different
    // instances, and a key pair generated through one reference must be visible through another
    // reference obtained by a separate GetShared() call for the same config (proving they really
    // are the same shared object, not just equivalent ones). Also exercises ResetShared() -- after
    // it, a fresh GetShared() call for a previously-used config must come back with no key pair
    // (GetSignatureSize()==0), proving the old cached instance was actually destroyed and a new one
    // built, not silently reused.
    int RunSharedInstanceTest(void);

    // Loops every ProviderKind x every RandomAlgorithm value (4x4=16 combinations) via
    // CCryptoApi::GenerateRandomBytes(algorithm, ...), cross-checked against
    // ICryptoProviderFactory::SupportsRandomAlgorithm() as ground truth -- supported combinations
    // must succeed AND produce different output across two independent calls (a same-output check
    // would silently pass a broken RNG returning all-zeros or a fixed buffer), unsupported ones
    // (e.g. RANDOM_CTR_DRBG on Microsoft/CryptoPP/Botan, RANDOM_HASH_DRBG on Microsoft/Botan) must
    // be cleanly rejected.
    int RunRandomAlgorithmsTest(void);

    // Round-trips EncryptString/DecryptString over English, Turkish and Japanese UTF-8 text to
    // confirm the API treats input as opaque UTF-8 bytes regardless of script/encoding width.
    int RunEncryptStringMultilingualTest(void);

    // Round-trips scalar char/short/int/long/float/double values (including zero, min/max,
    // negative, NaN and infinity) through EncryptBuffer/DecryptBuffer, byte-exact.
    int RunPrimitiveDataTest(void);

    // Same as RunPrimitiveDataTest but for whole arrays of each primitive type.
    int RunPrimitiveArrayDataTest(void);

    // Round-trips data held in std::vector containers: a vector<std::string> (each element
    // encrypted independently via EncryptString/DecryptString) and vector<short>/vector<double>
    // (each encrypted as one contiguous buffer via EncryptBuffer/DecryptBuffer).
    int RunVectorDataTest(void);

    // Round-trips a std::vector<std::wstring> by converting each element to UTF-8 before
    // EncryptString and back to std::wstring after DecryptString (CCryptoApi's string API is
    // UTF-8 only; wide strings are not passed to it directly).
    int RunVectorWideStringDataTest(void);

    // Exercises the provider/algorithm Factory pattern (CreateProviderFactory) directly: for each
    // ProviderKind, requests a factory, uses it to construct an IAeadCipher/ILegacyCipher for one
    // algorithm known to be supported and one known to be unsupported by that specific provider,
    // and round-trips data purely through the abstract interfaces the factory returns.
    int RunProviderFactoryTest(void);

    // File-based analogue of RunEncryptDecryptFileTest, but driven entirely by the Factory
    // pattern instead of CCryptoApi's fixed CMicrosoftProvider: for each ProviderKind, writes an
    // input file, encrypts it to disk via IAeadCipher::EncryptChunked (with progress reporting,
    // just like EncryptFile), decrypts it back from disk via DecryptChunked with a second cipher
    // instance from the same factory, and compares bytes.
    int RunProviderFactoryFileTest(void);

    // In-memory analogues of RunEncryptDecryptStringTest/BufferTest/BytesTest, driven by the
    // Factory pattern: for each ProviderKind, round-trips the same payload shape (text, binary
    // buffer, raw bytes) purely through a factory-selected IAeadCipher (AES-256-GCM). Just like
    // CCryptoApi's own EncryptBuffer/EncryptBytes (both thin wrappers over the same private
    // helper), the Buffer and Bytes variants here share one internal round-trip routine too.
    int RunProviderFactoryStringTest(void);

    int RunProviderFactoryBufferTest(void);

    int RunProviderFactoryBytesTest(void);

    // Hash analogues of RunProviderFactoryTest/FileTest/StringTest/BufferTest/BytesTest, driven
    // entirely by the Factory pattern (ICryptoProviderFactory::CreateHashService) instead of
    // CCryptoApi: RunProviderFactoryHashTest exercises SupportsHashAlgorithm/CreateHashService for
    // one supported and one unsupported algorithm per provider, and additionally proves the
    // incremental Init/Update/Final path agrees with the one-shot ComputeHash path. The File/
    // String/Buffer/Bytes variants cross-check the raw Factory-computed digest against
    // CCryptoApi::ComputeHashBuffer (via the Hash-only 2-argument constructor) for the same
    // content, proving the facade doesn't diverge from the lower-level Factory it wraps.
    int RunProviderFactoryHashTest(void);

    int RunProviderFactoryHashFileTest(void);

    int RunProviderFactoryHashStringTest(void);

    int RunProviderFactoryHashBufferTest(void);

    int RunProviderFactoryHashBytesTest(void);

    // Selects PROVIDER_MICROSOFT via the Factory and exercises every AeadAlgorithm/
    // LegacySymmetricAlgorithm/AsymmetricAlgorithm value the enums define: algorithms Microsoft/
    // CNG actually supports get a full round-trip (SetKey/Encrypt/Decrypt for symmetric,
    // GenerateKeyPair/Encrypt/Decrypt for RSA), the rest are verified as correctly rejected by
    // SupportsAeadAlgorithm/SupportsLegacyAlgorithm/SupportsAsymmetricAlgorithm. Nothing here is
    // hardcoded to "GCM only" -- whatever CreateProviderFactory(PROVIDER_MICROSOFT) reports as
    // supported gets tested.
    int RunMicrosoftProviderAllAlgorithmsTest(void);

    // Same as RunMicrosoftProviderAllAlgorithmsTest, but selecting PROVIDER_CRYPTOPP instead.
    int RunCryptoPPProviderAllAlgorithmsTest(void);

    // Same as RunMicrosoftProviderAllAlgorithmsTest, but selecting PROVIDER_BOTAN instead.
    int RunBotanProviderAllAlgorithmsTest(void);

    // Same as RunMicrosoftProviderAllAlgorithmsTest, but selecting PROVIDER_OPENSSL instead.
    int RunOpenSslProviderAllAlgorithmsTest(void);

    // Demonstrates that CCryptoApi's blocking calls can be driven from a background thread the
    // caller owns; CCryptoApi itself stays synchronous by design (see Rules.md/Plan.md ABI notes).
    int RunEncryptDecryptFileTestNonBlocking(void);

    int RunEncryptDecryptStringTestNonBlocking(void);

    int RunEncryptDecryptBufferTestNonBlocking(void);

    int RunEncryptDecryptBytesTestNonBlocking(void);

    // Hash analogues of RunEncryptDecryptFileTestNonBlocking/StringTestNonBlocking/
    // BufferTestNonBlocking/BytesTestNonBlocking, driving RunHashFileTest/StringTest/BufferTest/
    // BytesTest from a background thread via the same runNonBlocking helper.
    int RunHashFileTestNonBlocking(void);

    int RunHashStringTestNonBlocking(void);

    int RunHashBufferTestNonBlocking(void);

    int RunHashBytesTestNonBlocking(void);

    // Generates an identity via CPgpEngine::GenerateKeyPair, checks GetKeyId reports a 16-hex-char
    // Key ID, and round-trips ExportPublicKeyArmored/ExportSecretKeyArmored through the
    // capacity=0 BUFFER_TOO_SMALL query convention before checking both exports carry the
    // expected "-----BEGIN PGP ... KEY BLOCK-----" armor framing.
    int RunPgpKeyGenerationTest(void);

    // Two CPgpEngine identities (alice/bob) exchange public keys via ExportPublicKeyArmored/
    // ImportPeerPublicKey, then round-trip a binary buffer through EncryptBuffer/DecryptBuffer
    // and a UTF-8 string through EncryptStringArmored/DecryptStringArmored, both byte-exact.
    int RunPgpEncryptDecryptTest(void);

    // alice signs a buffer with SignBuffer; bob (having imported alice's public key) verifies it
    // with VerifyBuffer. A bit-flipped signature is confirmed to verify as *isValid=false (not a
    // technical error), matching CCryptoApi::VerifyBuffer's own convention.
    int RunPgpSignVerifyTest(void);

    // alice produces a clear-signed block via ClearSignString; bob verifies it via
    // VerifyClearSignedString. Tampering with the clear-signed body text is confirmed to flip
    // *isValid to false.
    int RunPgpClearSignTest(void);

    // Round-trips EncryptStringArmored/DecryptStringArmored (exercising the ASCII armor + CRC24
    // path end to end), then flips one base64 character in the armored message and confirms
    // DecryptStringArmored fails closed (INVALID_DATA) instead of returning corrupted plaintext.
    int RunPgpArmorTest(void);

    // End-to-end scenario test with four independent identities (Bob, Alice, Carol, Dave), each
    // generating its own PGP key pair (GenerateKeyPair) and exporting its public key
    // (ExportPublicKeyArmored). The test document is a real file on disk, written then read back
    // (same WriteTesterFile/ReadTesterFile + std::remove pattern as RunEncryptDecryptFileTest) to
    // exercise real file I/O, not just an in-memory literal. Bob signs that document once
    // (SignBuffer) and separately encrypts the signature-plus-document to each of Alice/Carol/
    // Dave's public keys in turn (ImportPeerPublicKey + EncryptBuffer per recipient -- this
    // engine has no multi-recipient PKESK support, so "sending to 3 people" means 3 independent
    // ciphertexts of the same signed payload, not one shared ciphertext). The signature and
    // document are framed together as a 4-byte big-endian signature length prefix followed by
    // the signature packet and then the document bytes, so each recipient can split them back
    // apart after decrypting. Each of Alice/Carol/Dave independently decrypts its own ciphertext
    // (DecryptBuffer) and verifies the signature against Bob's public key (VerifyBuffer),
    // confirming both the recovered document bytes and the signature's validity; Dave's copy is
    // additionally tampered with to confirm a corrupted signature is correctly rejected.
    int RunPgpAliceBobTest(void);

protected:

private:

    int runNonBlocking(const char* testName, int (CCryptoApiTester::*testMethod)(void));

};

} // namespace CryptoApiNS

#endif

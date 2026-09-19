#ifndef CRYPTOAPI_PROVIDERS_PROVIDER_TYPES_H
#define CRYPTOAPI_PROVIDERS_PROVIDER_TYPES_H

namespace CryptoApiNS
{

// Which underlying crypto library backs a provider. Passed to CreateProviderFactory() to select
// the concrete ICryptoProviderFactory implementation.
enum ProviderKind
{
    PROVIDER_MICROSOFT = 0,
    PROVIDER_CRYPTOPP = 1,
    PROVIDER_BOTAN = 2,
    PROVIDER_OPENSSL = 3,

    // libgcrypt (GnuPG's crypto library). x64 only -- the vendored bundle
    // (3rdParty/libgcryptbundle11241) has no Win32/x86 binary, so under a Win32 configuration this
    // provider still exists and is still selectable, but reports every algorithm as unsupported
    // (see CLibgcryptProvider's own header comment).
    PROVIDER_LIBGCRYPT = 4
};

// Authenticated (AEAD) cipher/mode/key-size combinations. Not every ProviderKind supports every
// value here; query ICryptoProviderFactory::SupportsAeadAlgorithm() before CreateAeadCipher().
enum AeadAlgorithm
{
    AEAD_AES_128_GCM = 0,
    AEAD_AES_192_GCM = 1,
    AEAD_AES_256_GCM = 2,
    AEAD_AES_128_CCM = 3,
    AEAD_AES_192_CCM = 4,
    AEAD_AES_256_CCM = 5,
    AEAD_AES_128_EAX = 6,
    AEAD_AES_192_EAX = 7,
    AEAD_AES_256_EAX = 8,
    AEAD_AES_128_SIV = 9,
    AEAD_AES_256_SIV = 10,
    AEAD_AES_128_GCM_SIV = 11,
    AEAD_AES_256_GCM_SIV = 12,
    AEAD_CHACHA20_POLY1305 = 13,
    AEAD_TWOFISH_GCM = 14,
    AEAD_SERPENT_GCM = 15,
    AEAD_CAMELLIA_GCM = 16
};

// Non-authenticated (no built-in integrity tag) symmetric cipher/mode/key-size combinations.
// These exist for legacy format interop only; CCryptoApi does not offer them as a default path.
// A caller needing integrity on top of one of these must pair it with a separate MAC service.
// Not every ProviderKind supports every value here; query
// ICryptoProviderFactory::SupportsLegacyAlgorithm() before CreateLegacyCipher().
enum LegacySymmetricAlgorithm
{
    LEGACY_AES_128_CBC = 0,
    LEGACY_AES_192_CBC = 1,
    LEGACY_AES_256_CBC = 2,
    LEGACY_AES_128_CTR = 3,
    LEGACY_AES_192_CTR = 4,
    LEGACY_AES_256_CTR = 5,
    LEGACY_AES_128_CFB = 6,
    LEGACY_AES_192_CFB = 7,
    LEGACY_AES_256_CFB = 8,
    LEGACY_AES_128_OFB = 9,
    LEGACY_AES_192_OFB = 10,
    LEGACY_AES_256_OFB = 11,
    LEGACY_AES_128_ECB = 12,
    LEGACY_AES_192_ECB = 13,
    LEGACY_AES_256_ECB = 14,

    // Legacy 64-bit-block/stream ciphers carried over from the old Windows CryptoAPI (CSP) world
    // (e.g. MS_ENH_RSA_AES_PROV). Windows CNG (BCrypt) still implements all of these, so they are
    // wired through CMicrosoftProvider; other providers report them unsupported unless/until they
    // are wired too. RC4 is a pure stream cipher: no chaining mode, no IV, no block padding -- and
    // its keystream position lives on the underlying key handle, so encrypting then decrypting
    // with the SAME ILegacyCipher instance requires calling SetKey() again (with the same key)
    // between the two calls to reset the stream back to position 0.

    LEGACY_RC2_CBC = 15,
    LEGACY_RC2_ECB = 16,
    LEGACY_DES_CBC = 17,
    LEGACY_DES_ECB = 18,
    LEGACY_3DES_CBC = 19,
    LEGACY_3DES_ECB = 20,
    LEGACY_RC4 = 21
};

// Asymmetric (public/private key-pair) algorithm/key-size combinations. Unlike AeadAlgorithm/
// LegacySymmetricAlgorithm there is no caller-supplied key: IAsymmetricCipher::GenerateKeyPair()
// creates a fresh key pair sized per the selected value. Not every ProviderKind supports every
// value here; query ICryptoProviderFactory::SupportsAsymmetricAlgorithm() before
// CreateAsymmetricCipher().
enum AsymmetricAlgorithm
{
    ASYMMETRIC_RSA_1024 = 0,
    ASYMMETRIC_RSA_2048 = 1,
    ASYMMETRIC_RSA_3072 = 2,
    ASYMMETRIC_RSA_4096 = 3
};

// Cryptographic hash algorithms. Unlike AeadAlgorithm/LegacySymmetricAlgorithm there is no key at
// all -- IHashService::ComputeHash()/Update()+Final() just digest input bytes. BLAKE2b and BLAKE2s
// are both variable-output-size algorithms in general; the values below mean their conventional
// full-size default (BLAKE2b-512, BLAKE2s-256), not a truncated variant. Not every ProviderKind
// supports every value here (in particular, Windows CNG's SHA-3 requires Windows 11 24H2/Server
// 2025 or newer, and CNG has no BLAKE2/RIPEMD-160 support at all); query
// ICryptoProviderFactory::SupportsHashAlgorithm() before CreateHashService().
enum HashAlgorithm
{
    HASH_MD5        = 0,
    HASH_SHA1       = 1,
    HASH_SHA224     = 2,
    HASH_SHA256     = 3,
    HASH_SHA384     = 4,
    HASH_SHA512     = 5,
    HASH_SHA512_256 = 6,
    HASH_SHA3_224   = 7,
    HASH_SHA3_256   = 8,
    HASH_SHA3_384   = 9,
    HASH_SHA3_512   = 10,
    HASH_BLAKE2B    = 11,
    HASH_BLAKE2S    = 12,
    HASH_RIPEMD160  = 13
};

// Digital signature algorithms. Like AsymmetricAlgorithm, GenerateKeyPair() creates a fresh key
// pair per selected value -- no caller-supplied key. Signature output is a fixed size for every
// value here (deterministic per algorithm/key size, see ISignatureEngine::GetSignatureSize):
// SIGNATURE_ECDSA_P256_SHA256 always produces the raw 64-byte r||s concatenation (32-byte r +
// 32-byte s, both big-endian, zero-padded), never variable-length ASN.1 DER -- providers whose
// native API produces DER (or vice versa) convert internally so every provider agrees on this one
// wire format. SIGNATURE_ECDSA_P384_SHA384/P521_SHA512 follow the same raw-r||s convention at
// their own component width: P-384 is 48+48=96 bytes, P-521 is 66+66=132 bytes (66 = ceil(521/8),
// the field-element byte width, not 521/8 rounded down). The paired hash (SHA-384/SHA-512) follows
// NIST SP 800-186's conventional curve/hash strength matching, not a free choice -- unlike
// SIGNATURE_RSA_PSS_SHA256_*, which stays SHA-256 at every RSA key size. SIGNATURE_DSA_SHA256_*
// (classic, non-elliptic-curve DSA, FIPS 186-4/186-5 with L=2048/3072, N=256) follows the same
// raw-r||s convention too, always 64 bytes (32+32) at either L, since N (the subgroup order size,
// which is what actually determines r/s width) is fixed at 256 bits for both -- included for
// completeness alongside RSA/ECDSA/EdDSA despite FIPS 186-5 deprecating DSA *signature generation*
// for new systems (kept here as a legacy-interop/completeness algorithm, not a recommended
// default -- see ISignatureEngine's own callers for guidance on algorithm choice). Not every
// ProviderKind supports every value here; query ICryptoProviderFactory::SupportsSignatureAlgorithm()
// before CreateSignatureEngine().
enum SignatureAlgorithm
{
    SIGNATURE_RSA_PSS_SHA256_2048 = 0,
    SIGNATURE_RSA_PSS_SHA256_3072 = 1,
    SIGNATURE_RSA_PSS_SHA256_4096 = 2,
    SIGNATURE_ECDSA_P256_SHA256   = 3,
    SIGNATURE_ED25519             = 4,
    SIGNATURE_ECDSA_P384_SHA384   = 5,
    SIGNATURE_ECDSA_P521_SHA512   = 6,
    SIGNATURE_DSA_SHA256_2048     = 7,
    SIGNATURE_DSA_SHA256_3072     = 8
};

// Key agreement (Diffie-Hellman style) algorithm/curve combinations. Like SignatureAlgorithm,
// GenerateKeyPair() creates a fresh key pair per selected value -- no caller-supplied key and no
// RSA analogue (RSA does not do key agreement). Shared secret output is a fixed size for every
// value here (see IKeyAgreementService::GetSharedSecretSize). Not every ProviderKind supports every
// value here; query ICryptoProviderFactory::SupportsKeyAgreementAlgorithm() before
// CreateKeyAgreementEngine(). Windows CNG has no X25519 support through a standard, documented API
// (only via a non-standard generic curve parameterization), so KEYAGREEMENT_X25519 is intentionally
// unsupported on PROVIDER_MICROSOFT -- same reasoning as SIGNATURE_ED25519 being unsupported there.
enum KeyAgreementAlgorithm
{
    KEYAGREEMENT_ECDH_P256 = 0,
    KEYAGREEMENT_X25519    = 1
};

// Random byte generation algorithms. RANDOM_SYSTEM is each provider's OS-preferred CSPRNG -- what
// IRandomSource::GenerateRandomBytes() already used unconditionally before this enum existed, and
// still the default when SelectAlgorithm() is never called (fully backward compatible: every
// existing internal nonce/IV/salt generation call site in this SDK is unaffected). The other 3
// values are NIST SP 800-90A's own named DRBG mechanisms (Hash_DRBG, HMAC_DRBG, CTR_DRBG),
// available where a provider ships an explicit, separately-selectable implementation of that exact
// mechanism -- not every provider does (Windows CNG's system RNG is internally CTR_DRBG-based per
// Microsoft's own documentation, but that is not exposed as a separately selectable algorithm
// through any stable public API, so RANDOM_CTR_DRBG is unsupported on PROVIDER_MICROSOFT rather
// than silently aliasing it to RANDOM_SYSTEM). Not every ProviderKind supports every value here;
// query ICryptoProviderFactory::SupportsRandomAlgorithm() before CreateRandomSource(algorithm).
enum RandomAlgorithm
{
    RANDOM_SYSTEM    = 0,
    RANDOM_HASH_DRBG = 1,
    RANDOM_HMAC_DRBG = 2,
    RANDOM_CTR_DRBG  = 3
};

} // namespace CryptoApiNS

#endif

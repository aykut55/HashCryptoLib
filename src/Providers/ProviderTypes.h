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
    PROVIDER_OPENSSL = 3
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
// wire format. Not every ProviderKind supports every value here; query
// ICryptoProviderFactory::SupportsSignatureAlgorithm() before CreateSignatureEngine().
enum SignatureAlgorithm
{
    SIGNATURE_RSA_PSS_SHA256_2048 = 0,
    SIGNATURE_RSA_PSS_SHA256_3072 = 1,
    SIGNATURE_RSA_PSS_SHA256_4096 = 2,
    SIGNATURE_ECDSA_P256_SHA256   = 3,
    SIGNATURE_ED25519             = 4
};

} // namespace CryptoApiNS

#endif

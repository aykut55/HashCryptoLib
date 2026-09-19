#include "LibgcryptProvider.h"

// The vendored libgcrypt bundle (3rdParty/libgcryptbundle11241) ships an x64 DLL plus an x64-only
// MSVC import library; no Win32/x86 build of libgcrypt exists. Rules.md guarantees ARCH_X64/
// ARCH_WIN64 (x64) and ARCH_X86/ARCH_WIN32 (Win32) are defined by every projects/msvc project, so
// those are the primary switch; _WIN64 is only a fallback for a build that defines neither (e.g. a
// standalone compile outside this repo's own project files). When this is 0, NOT ONE gcry_* call --
// and not even gcrypt.h itself -- is compiled in, and every method below reports "unsupported"
// (false, or 0 for the size queries), the same honest-unsupported convention CMicrosoftProvider
// already uses for SIGNATURE_ED25519/KEYAGREEMENT_X25519.
#if defined(ARCH_X64) || defined(ARCH_WIN64)
#define CRYPTOAPI_LIBGCRYPT_AVAILABLE 1
#elif defined(ARCH_X86) || defined(ARCH_WIN32)
#define CRYPTOAPI_LIBGCRYPT_AVAILABLE 0
#elif defined(_WIN64)
#define CRYPTOAPI_LIBGCRYPT_AVAILABLE 1
#else
#define CRYPTOAPI_LIBGCRYPT_AVAILABLE 0
#endif

#if CRYPTOAPI_LIBGCRYPT_AVAILABLE

#include "gcrypt.h"

#include <cstring>
#include <vector>

namespace CryptoApiNS
{

namespace
{
    // Every AEAD algorithm this provider exposes uses libgcrypt's full 16-byte authentication tag.
    const unsigned int LIBGCRYPT_PROVIDER_TAG_SIZE = 16;

    // Oldest libgcrypt this provider's API usage is valid against; gcry_check_version() refuses
    // (returns NULL) if the loaded DLL is older, which is exactly the behaviour we want.
    const char* const LIBGCRYPT_PROVIDER_MINIMUM_VERSION = "1.8.0";

    // libgcrypt demands a one-time, process-wide initialization handshake before any other gcry_*
    // call: gcry_check_version() first, then GCRYCTL_INITIALIZATION_FINISHED. Secure (mlock'ed)
    // memory is deliberately disabled -- this SDK never asks libgcrypt for a secmem pool, and
    // leaving it enabled makes libgcrypt emit a runtime warning on every allocation that would have
    // wanted it. A function-local static gives C++11 magic-static thread safety, so concurrently
    // constructed CLibgcryptProvider instances still initialize the library exactly once.
    bool InitializeLibraryOnce(void)
    {
        static const bool initialized = []() -> bool
        {
            if (gcry_check_version(LIBGCRYPT_PROVIDER_MINIMUM_VERSION) == nullptr)
            {
                return false;
            }

            gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
            gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
            return true;
        }();

        return initialized;
    }
    // -----------------------------------------------------------------------------

    // --- AEAD (IAeadCipher) ----------------------------------------------------------------------

    struct AeadSpec
    {
        int cipherAlgorithm;
        int cipherMode;
        unsigned int keySize;
        unsigned int nonceSize;
    };

    // libgcrypt covers every AeadAlgorithm value this SDK defines -- the only provider of the five
    // that does. Two shapes need explaining:
    //   * SIV (RFC 5297) takes a DOUBLE-length key: the S2V half and the CTR half. So "AES-128-SIV"
    //     is GCRY_CIPHER_AES (a 128-bit AES) driven by a 32-byte key, and "AES-256-SIV" is
    //     GCRY_CIPHER_AES256 driven by a 64-byte key. This matches Botan's own AES-128/SIV and
    //     AES-256/SIV key sizes, so the two providers agree on what those enum values mean.
    //   * GCM-SIV (RFC 8452) is defined only for 128-bit and 256-bit keys and, unlike plain SIV,
    //     uses an ordinary single-length key.
    // SIV's nonce is arbitrary-length in the spec; 16 bytes is used here (Botan's own default
    // nonce length for SIV too). Everything else uses the conventional 12-byte nonce.
    bool AeadAlgorithmSpec(const AeadAlgorithm algorithm, AeadSpec* spec)
    {
        switch (algorithm)
        {
        case AEAD_AES_128_GCM:       spec->cipherAlgorithm = GCRY_CIPHER_AES;       spec->cipherMode = GCRY_CIPHER_MODE_GCM;      spec->keySize = 16; spec->nonceSize = 12; return true;
        case AEAD_AES_192_GCM:       spec->cipherAlgorithm = GCRY_CIPHER_AES192;    spec->cipherMode = GCRY_CIPHER_MODE_GCM;      spec->keySize = 24; spec->nonceSize = 12; return true;
        case AEAD_AES_256_GCM:       spec->cipherAlgorithm = GCRY_CIPHER_AES256;    spec->cipherMode = GCRY_CIPHER_MODE_GCM;      spec->keySize = 32; spec->nonceSize = 12; return true;
        case AEAD_AES_128_CCM:       spec->cipherAlgorithm = GCRY_CIPHER_AES;       spec->cipherMode = GCRY_CIPHER_MODE_CCM;      spec->keySize = 16; spec->nonceSize = 12; return true;
        case AEAD_AES_192_CCM:       spec->cipherAlgorithm = GCRY_CIPHER_AES192;    spec->cipherMode = GCRY_CIPHER_MODE_CCM;      spec->keySize = 24; spec->nonceSize = 12; return true;
        case AEAD_AES_256_CCM:       spec->cipherAlgorithm = GCRY_CIPHER_AES256;    spec->cipherMode = GCRY_CIPHER_MODE_CCM;      spec->keySize = 32; spec->nonceSize = 12; return true;
        case AEAD_AES_128_EAX:       spec->cipherAlgorithm = GCRY_CIPHER_AES;       spec->cipherMode = GCRY_CIPHER_MODE_EAX;      spec->keySize = 16; spec->nonceSize = 12; return true;
        case AEAD_AES_192_EAX:       spec->cipherAlgorithm = GCRY_CIPHER_AES192;    spec->cipherMode = GCRY_CIPHER_MODE_EAX;      spec->keySize = 24; spec->nonceSize = 12; return true;
        case AEAD_AES_256_EAX:       spec->cipherAlgorithm = GCRY_CIPHER_AES256;    spec->cipherMode = GCRY_CIPHER_MODE_EAX;      spec->keySize = 32; spec->nonceSize = 12; return true;
        case AEAD_AES_128_SIV:       spec->cipherAlgorithm = GCRY_CIPHER_AES;       spec->cipherMode = GCRY_CIPHER_MODE_SIV;      spec->keySize = 32; spec->nonceSize = 16; return true;
        case AEAD_AES_256_SIV:       spec->cipherAlgorithm = GCRY_CIPHER_AES256;    spec->cipherMode = GCRY_CIPHER_MODE_SIV;      spec->keySize = 64; spec->nonceSize = 16; return true;
        case AEAD_AES_128_GCM_SIV:   spec->cipherAlgorithm = GCRY_CIPHER_AES;       spec->cipherMode = GCRY_CIPHER_MODE_GCM_SIV;  spec->keySize = 16; spec->nonceSize = 12; return true;
        case AEAD_AES_256_GCM_SIV:   spec->cipherAlgorithm = GCRY_CIPHER_AES256;    spec->cipherMode = GCRY_CIPHER_MODE_GCM_SIV;  spec->keySize = 32; spec->nonceSize = 12; return true;
        case AEAD_CHACHA20_POLY1305: spec->cipherAlgorithm = GCRY_CIPHER_CHACHA20;  spec->cipherMode = GCRY_CIPHER_MODE_POLY1305; spec->keySize = 32; spec->nonceSize = 12; return true;
        case AEAD_TWOFISH_GCM:       spec->cipherAlgorithm = GCRY_CIPHER_TWOFISH;   spec->cipherMode = GCRY_CIPHER_MODE_GCM;      spec->keySize = 32; spec->nonceSize = 12; return true;
        case AEAD_SERPENT_GCM:       spec->cipherAlgorithm = GCRY_CIPHER_SERPENT256; spec->cipherMode = GCRY_CIPHER_MODE_GCM;     spec->keySize = 32; spec->nonceSize = 12; return true;
        case AEAD_CAMELLIA_GCM:      spec->cipherAlgorithm = GCRY_CIPHER_CAMELLIA256; spec->cipherMode = GCRY_CIPHER_MODE_GCM;    spec->keySize = 32; spec->nonceSize = 12; return true;
        default:
            return false;
        }
    }
    // -----------------------------------------------------------------------------

    // --- Legacy symmetric (ILegacyCipher) --------------------------------------------------------

    struct LegacySpec
    {
        int cipherAlgorithm;
        int cipherMode;
        unsigned int keySize;
        bool usesIv;
        bool padded;
    };

    // libgcrypt covers every LegacySymmetricAlgorithm value too, including the old Windows-CSP-era
    // RC2/DES/3DES/RC4 rows that only CMicrosoftProvider handled before. libgcrypt performs NO
    // block padding of its own (unlike OpenSSL's EVP layer), so the CBC/ECB rows are marked padded
    // here and this provider applies/strips PKCS#7 itself -- see Encrypt/Decrypt below.
    // RFC2268_128 is RC2 with a 128-bit key, matching CNG's own RC2 default key length.
    bool LegacyAlgorithmSpec(const LegacySymmetricAlgorithm algorithm, LegacySpec* spec)
    {
        switch (algorithm)
        {
        case LEGACY_AES_128_CBC: spec->cipherAlgorithm = GCRY_CIPHER_AES;    spec->cipherMode = GCRY_CIPHER_MODE_CBC;    spec->keySize = 16; spec->usesIv = true;  spec->padded = true;  return true;
        case LEGACY_AES_192_CBC: spec->cipherAlgorithm = GCRY_CIPHER_AES192; spec->cipherMode = GCRY_CIPHER_MODE_CBC;    spec->keySize = 24; spec->usesIv = true;  spec->padded = true;  return true;
        case LEGACY_AES_256_CBC: spec->cipherAlgorithm = GCRY_CIPHER_AES256; spec->cipherMode = GCRY_CIPHER_MODE_CBC;    spec->keySize = 32; spec->usesIv = true;  spec->padded = true;  return true;
        case LEGACY_AES_128_CTR: spec->cipherAlgorithm = GCRY_CIPHER_AES;    spec->cipherMode = GCRY_CIPHER_MODE_CTR;    spec->keySize = 16; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_192_CTR: spec->cipherAlgorithm = GCRY_CIPHER_AES192; spec->cipherMode = GCRY_CIPHER_MODE_CTR;    spec->keySize = 24; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_256_CTR: spec->cipherAlgorithm = GCRY_CIPHER_AES256; spec->cipherMode = GCRY_CIPHER_MODE_CTR;    spec->keySize = 32; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_128_CFB: spec->cipherAlgorithm = GCRY_CIPHER_AES;    spec->cipherMode = GCRY_CIPHER_MODE_CFB;    spec->keySize = 16; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_192_CFB: spec->cipherAlgorithm = GCRY_CIPHER_AES192; spec->cipherMode = GCRY_CIPHER_MODE_CFB;    spec->keySize = 24; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_256_CFB: spec->cipherAlgorithm = GCRY_CIPHER_AES256; spec->cipherMode = GCRY_CIPHER_MODE_CFB;    spec->keySize = 32; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_128_OFB: spec->cipherAlgorithm = GCRY_CIPHER_AES;    spec->cipherMode = GCRY_CIPHER_MODE_OFB;    spec->keySize = 16; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_192_OFB: spec->cipherAlgorithm = GCRY_CIPHER_AES192; spec->cipherMode = GCRY_CIPHER_MODE_OFB;    spec->keySize = 24; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_256_OFB: spec->cipherAlgorithm = GCRY_CIPHER_AES256; spec->cipherMode = GCRY_CIPHER_MODE_OFB;    spec->keySize = 32; spec->usesIv = true;  spec->padded = false; return true;
        case LEGACY_AES_128_ECB: spec->cipherAlgorithm = GCRY_CIPHER_AES;    spec->cipherMode = GCRY_CIPHER_MODE_ECB;    spec->keySize = 16; spec->usesIv = false; spec->padded = true;  return true;
        case LEGACY_AES_192_ECB: spec->cipherAlgorithm = GCRY_CIPHER_AES192; spec->cipherMode = GCRY_CIPHER_MODE_ECB;    spec->keySize = 24; spec->usesIv = false; spec->padded = true;  return true;
        case LEGACY_AES_256_ECB: spec->cipherAlgorithm = GCRY_CIPHER_AES256; spec->cipherMode = GCRY_CIPHER_MODE_ECB;    spec->keySize = 32; spec->usesIv = false; spec->padded = true;  return true;
        case LEGACY_RC2_CBC:     spec->cipherAlgorithm = GCRY_CIPHER_RFC2268_128; spec->cipherMode = GCRY_CIPHER_MODE_CBC; spec->keySize = 16; spec->usesIv = true;  spec->padded = true;  return true;
        case LEGACY_RC2_ECB:     spec->cipherAlgorithm = GCRY_CIPHER_RFC2268_128; spec->cipherMode = GCRY_CIPHER_MODE_ECB; spec->keySize = 16; spec->usesIv = false; spec->padded = true;  return true;
        case LEGACY_DES_CBC:     spec->cipherAlgorithm = GCRY_CIPHER_DES;    spec->cipherMode = GCRY_CIPHER_MODE_CBC;    spec->keySize = 8;  spec->usesIv = true;  spec->padded = true;  return true;
        case LEGACY_DES_ECB:     spec->cipherAlgorithm = GCRY_CIPHER_DES;    spec->cipherMode = GCRY_CIPHER_MODE_ECB;    spec->keySize = 8;  spec->usesIv = false; spec->padded = true;  return true;
        case LEGACY_3DES_CBC:    spec->cipherAlgorithm = GCRY_CIPHER_3DES;   spec->cipherMode = GCRY_CIPHER_MODE_CBC;    spec->keySize = 24; spec->usesIv = true;  spec->padded = true;  return true;
        case LEGACY_3DES_ECB:    spec->cipherAlgorithm = GCRY_CIPHER_3DES;   spec->cipherMode = GCRY_CIPHER_MODE_ECB;    spec->keySize = 24; spec->usesIv = false; spec->padded = true;  return true;
        case LEGACY_RC4:         spec->cipherAlgorithm = GCRY_CIPHER_ARCFOUR; spec->cipherMode = GCRY_CIPHER_MODE_STREAM; spec->keySize = 16; spec->usesIv = false; spec->padded = false; return true;
        default:
            return false;
        }
    }
    // -----------------------------------------------------------------------------

    // --- Hash (IHashService) ---------------------------------------------------------------------

    // libgcrypt implements every one of this SDK's 14 HashAlgorithm values (verified at runtime
    // against gcry_md_test_algo and known "abc" digests). BLAKE2b/BLAKE2s map to their conventional
    // full-size variants (BLAKE2b-512, BLAKE2s-256) per HashAlgorithm's own doc comment.
    int HashAlgorithmId(const HashAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case HASH_MD5:        return GCRY_MD_MD5;
        case HASH_SHA1:       return GCRY_MD_SHA1;
        case HASH_SHA224:     return GCRY_MD_SHA224;
        case HASH_SHA256:     return GCRY_MD_SHA256;
        case HASH_SHA384:     return GCRY_MD_SHA384;
        case HASH_SHA512:     return GCRY_MD_SHA512;
        case HASH_SHA512_256: return GCRY_MD_SHA512_256;
        case HASH_SHA3_224:   return GCRY_MD_SHA3_224;
        case HASH_SHA3_256:   return GCRY_MD_SHA3_256;
        case HASH_SHA3_384:   return GCRY_MD_SHA3_384;
        case HASH_SHA3_512:   return GCRY_MD_SHA3_512;
        case HASH_BLAKE2B:    return GCRY_MD_BLAKE2B_512;
        case HASH_BLAKE2S:    return GCRY_MD_BLAKE2S_256;
        case HASH_RIPEMD160:  return GCRY_MD_RMD160;
        default:              return GCRY_MD_NONE;
        }
    }
    // -----------------------------------------------------------------------------

    // --- Asymmetric (RSA-OAEP-SHA256) ------------------------------------------------------------

    unsigned int AsymmetricKeyBits(const AsymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case ASYMMETRIC_RSA_1024: return 1024;
        case ASYMMETRIC_RSA_2048: return 2048;
        case ASYMMETRIC_RSA_3072: return 3072;
        case ASYMMETRIC_RSA_4096: return 4096;
        default:                  return 0;
        }
    }
    // -----------------------------------------------------------------------------

    // --- Signature (ISignatureEngine) ------------------------------------------------------------

    // 0 for non-RSA algorithms (ECDSA, Ed25519, DSA), which have a fixed key size or their own
    // parameter-bits query instead.
    unsigned int SignatureRsaKeyBits(const SignatureAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case SIGNATURE_RSA_PSS_SHA256_2048: return 2048;
        case SIGNATURE_RSA_PSS_SHA256_3072: return 3072;
        case SIGNATURE_RSA_PSS_SHA256_4096: return 4096;
        default:                            return 0;
        }
    }
    // -----------------------------------------------------------------------------

    // 0 for non-DSA algorithms. DSA's L (2048/3072) pairs with an explicitly pinned N of 256 bits
    // (qbits, see GenerateKeyPair) so the raw r||s signature is 64 bytes at either L.
    unsigned int SignatureDsaParamBits(const SignatureAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case SIGNATURE_DSA_SHA256_2048: return 2048;
        case SIGNATURE_DSA_SHA256_3072: return 3072;
        default:                        return 0;
        }
    }
    // -----------------------------------------------------------------------------

    // libgcrypt curve name for the "(genkey (ecc (curve ...)))" S-expression; nullptr for the
    // non-ECC algorithms. These are libgcrypt's own canonical spellings (see its ecc-curves.c
    // alias table): "NIST P-256"/"NIST P-384"/"NIST P-521" and "Ed25519".
    const char* SignatureCurveName(const SignatureAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case SIGNATURE_ECDSA_P256_SHA256: return "NIST P-256";
        case SIGNATURE_ECDSA_P384_SHA384: return "NIST P-384";
        case SIGNATURE_ECDSA_P521_SHA512: return "NIST P-521";
        case SIGNATURE_ED25519:           return "Ed25519";
        default:                          return nullptr;
        }
    }
    // -----------------------------------------------------------------------------

    // Raw r/s component width in bytes for the ECDSA algorithms (r||s signature size is 2x this);
    // 0 for everything else. P-521's 521-bit field rounds UP to 66 bytes (ceil(521/8)), not 65.
    unsigned int SignatureEcdsaComponentBytes(const SignatureAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case SIGNATURE_ECDSA_P256_SHA256: return 32;
        case SIGNATURE_ECDSA_P384_SHA384: return 48;
        case SIGNATURE_ECDSA_P521_SHA512: return 66;
        default:                          return 0;
        }
    }
    // -----------------------------------------------------------------------------

    // Digest paired with each signature algorithm. RSA-PSS stays SHA-256 at every key size; ECDSA
    // follows NIST SP 800-186's conventional curve/hash strength matching; DSA is SHA-256 at both
    // L values. Ed25519 has no separately selectable digest here (RFC 8032 pins SHA-512 internally,
    // passed to libgcrypt as the eddsa data S-expression's hash-algo).
    int SignatureDigestAlgorithm(const SignatureAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case SIGNATURE_ECDSA_P384_SHA384: return GCRY_MD_SHA384;
        case SIGNATURE_ECDSA_P521_SHA512: return GCRY_MD_SHA512;
        default:                          return GCRY_MD_SHA256;
        }
    }
    // -----------------------------------------------------------------------------

    // --- Key agreement (IKeyAgreementService) ----------------------------------------------------

    // KEYAGREEMENT_ECDH_P256: SEC1 uncompressed point (0x04||X||Y), 1 + 2*32 bytes -- exactly what
    // libgcrypt stores in an ECC key's "q" parameter. KEYAGREEMENT_X25519: raw 32-byte u-coordinate.
    unsigned int KeyAgreementPublicKeySize(const KeyAgreementAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case KEYAGREEMENT_ECDH_P256: return 1u + 2u * 32u;
        case KEYAGREEMENT_X25519:    return 32u;
        default:                     return 0;
        }
    }
    // -----------------------------------------------------------------------------

    // Both curves produce a 32-byte shared secret (P-256: the raw X-coordinate of the agreed point,
    // left-zero-padded to the field width; X25519: gcry_ecc_mul_point's native output size).
    unsigned int KeyAgreementSharedSecretSize(const KeyAgreementAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case KEYAGREEMENT_ECDH_P256: return 32u;
        case KEYAGREEMENT_X25519:    return 32u;
        default:                     return 0;
        }
    }
    // -----------------------------------------------------------------------------

    // --- Shared S-expression / MPI helpers -------------------------------------------------------

    // Writes an MPI into a FIXED-width, left-zero-padded big-endian buffer. libgcrypt's
    // GCRYMPI_FMT_USG always emits the minimal representation (leading zero bytes dropped), but
    // every wire format this SDK promises -- RSA ciphertext/signature at exactly the modulus size,
    // ECDSA/DSA r||s at exactly the component width, an ECDH X-coordinate at the field width -- is
    // fixed-size, so the padding has to be reinstated here.
    bool MpiToFixedBuffer(gcry_mpi_t value, unsigned char* output, const unsigned int outputSize)
    {
        if (value == nullptr || output == nullptr || outputSize == 0)
        {
            return false;
        }

        std::vector<unsigned char> minimal(outputSize);
        std::size_t written = 0;
        if (gcry_mpi_print(GCRYMPI_FMT_USG, minimal.data(), outputSize, &written, value) != 0 ||
            written > outputSize)
        {
            return false;
        }

        std::memset(output, 0, outputSize);
        std::memcpy(output + (outputSize - written), minimal.data(), written);
        return true;
    }
    // -----------------------------------------------------------------------------

    // Finds a single-value token (e.g. "s", "r", "a", "q", "d") inside an S-expression and writes
    // its value into a fixed-width buffer via MpiToFixedBuffer.
    bool SexpTokenToFixedBuffer(gcry_sexp_t container, const char* token, unsigned char* output, const unsigned int outputSize)
    {
        if (container == nullptr || token == nullptr)
        {
            return false;
        }

        gcry_sexp_t element = gcry_sexp_find_token(container, token, 0);
        if (element == nullptr)
        {
            return false;
        }

        gcry_mpi_t value = gcry_sexp_nth_mpi(element, 1, GCRYMPI_FMT_USG);
        const bool converted = MpiToFixedBuffer(value, output, outputSize);

        if (value != nullptr)
        {
            gcry_mpi_release(value);
        }
        gcry_sexp_release(element);
        return converted;
    }
    // -----------------------------------------------------------------------------

    // EdDSA's r/s live in the signature S-expression as opaque fixed-width byte strings rather than
    // arithmetic MPIs (r is a little-endian point encoding, not a number), so they are read with
    // gcry_sexp_nth_data and right-aligned rather than going through the MPI path above.
    bool SexpTokenToRawBuffer(gcry_sexp_t container, const char* token, unsigned char* output, const unsigned int outputSize)
    {
        if (container == nullptr || token == nullptr || output == nullptr || outputSize == 0)
        {
            return false;
        }

        gcry_sexp_t element = gcry_sexp_find_token(container, token, 0);
        if (element == nullptr)
        {
            return false;
        }

        std::size_t dataSize = 0;
        const char* data = gcry_sexp_nth_data(element, 1, &dataSize);
        bool copied = false;
        if (data != nullptr && dataSize > 0 && dataSize <= outputSize)
        {
            std::memset(output, 0, outputSize);
            std::memcpy(output + (outputSize - dataSize), data, dataSize);
            copied = true;
        }

        gcry_sexp_release(element);
        return copied;
    }
    // -----------------------------------------------------------------------------

    // Builds the "(data ...)" S-expression gcry_pk_sign/gcry_pk_verify consume, in whichever shape
    // the selected algorithm's libgcrypt backend expects: PSS padding for RSA, a raw pre-hashed
    // value for ECDSA/DSA, and the whole un-hashed message for Ed25519 (RFC 8032 is not a
    // pre-hashed scheme). Returns nullptr on failure; the caller owns the result.
    gcry_sexp_t BuildSignatureDataSexp(const SignatureAlgorithm algorithm, const unsigned char* data, const unsigned int dataSize)
    {
        gcry_sexp_t dataSexp = nullptr;

        if (algorithm == SIGNATURE_ED25519)
        {
            if (gcry_sexp_build(&dataSexp, nullptr, "(data (flags eddsa) (hash-algo sha512) (value %b))",
                                static_cast<int>(dataSize), reinterpret_cast<const char*>(data)) != 0)
            {
                return nullptr;
            }
            return dataSexp;
        }

        const int digestAlgorithm = SignatureDigestAlgorithm(algorithm);
        const unsigned int digestSize = gcry_md_get_algo_dlen(digestAlgorithm);
        if (digestSize == 0 || digestSize > 64)
        {
            return nullptr;
        }

        unsigned char digest[64];
        gcry_md_hash_buffer(digestAlgorithm, digest, data, dataSize);

        if (SignatureRsaKeyBits(algorithm) != 0)
        {
            // RSA-PSS with libgcrypt's default salt length (equal to the digest length), matching
            // RSA_PSS_SALTLEN_DIGEST on the OpenSSL provider and Botan's PSS(SHA-256).
            if (gcry_sexp_build(&dataSexp, nullptr, "(data (flags pss) (hash %s %b))",
                                gcry_md_algo_name(digestAlgorithm),
                                static_cast<int>(digestSize), reinterpret_cast<const char*>(digest)) != 0)
            {
                return nullptr;
            }
            return dataSexp;
        }

        if (SignatureEcdsaComponentBytes(algorithm) != 0)
        {
            if (gcry_sexp_build(&dataSexp, nullptr, "(data (flags raw) (hash %s %b))",
                                gcry_md_algo_name(digestAlgorithm),
                                static_cast<int>(digestSize), reinterpret_cast<const char*>(digest)) != 0)
            {
                return nullptr;
            }
            return dataSexp;
        }

        if (SignatureDsaParamBits(algorithm) != 0)
        {
            // libgcrypt's DSA backend wants the digest as a plain MPI value, not the (hash ...)
            // form the ECDSA backend accepts.
            gcry_mpi_t digestMpi = nullptr;
            if (gcry_mpi_scan(&digestMpi, GCRYMPI_FMT_USG, digest, digestSize, nullptr) != 0)
            {
                return nullptr;
            }

            const int status = gcry_sexp_build(&dataSexp, nullptr, "(data (flags raw) (value %m))", digestMpi);
            gcry_mpi_release(digestMpi);
            if (status != 0)
            {
                return nullptr;
            }
            return dataSexp;
        }

        return nullptr;
    }
    // -----------------------------------------------------------------------------
}

struct CLibgcryptProvider::Impl
{
    // Symmetric state (shared by IAeadCipher and ILegacyCipher; legacySelected says which one the
    // most recent SelectAlgorithm configured). A gcry_cipher_hd_t is deliberately NOT cached here:
    // libgcrypt's cipher handles carry per-message state (IV/counter/AEAD accumulators) that must
    // be reset for every operation anyway, so Encrypt/Decrypt open a fresh handle each call. That
    // also means LEGACY_RC4's keystream position always restarts at 0, so -- unlike the note on
    // LegacySymmetricAlgorithm's RC4 row -- no extra SetKey() is needed between encrypt and decrypt.
    bool symmetricSelected;
    bool legacySelected;
    int cipherAlgorithm;
    int cipherMode;
    unsigned int keySize;
    unsigned int ivOrNonceSize;
    unsigned int tagSize;
    unsigned int blockSize;
    bool legacyPadded;
    bool aeadIsCcm;
    bool aeadNeedsDecryptionTag;
    std::vector<unsigned char> key;

    // IAsymmetricCipher state (RSA-OAEP-SHA256).
    unsigned int rsaKeyBits;
    bool rsaKeyGenerated;
    gcry_sexp_t rsaPublicKey;
    gcry_sexp_t rsaPrivateKey;

    // IHashService state. hashHandle is the mutable digest state, reset via gcry_md_reset for each
    // Init(); hashAlgorithm/hashSize come from the selected HashAlgorithm.
    int hashAlgorithm;
    unsigned int hashSize;
    gcry_md_hd_t hashHandle;

    // ISignatureEngine state -- a separate key pair from rsaPublicKey/rsaPrivateKey above (that is
    // RSA-OAEP encryption; this is RSA-PSS/ECDSA/EdDSA/DSA signing, a distinct key even when both
    // happen to be RSA). asymmetricModeIsSignature dispatches GenerateKeyPair() (shared with
    // IAsymmetricCipher, see the header comment).
    bool asymmetricModeIsSignature;
    SignatureAlgorithm signatureAlgorithm;
    bool signatureKeyGenerated;
    unsigned int signatureSize;
    gcry_sexp_t signaturePublicKey;
    gcry_sexp_t signaturePrivateKey;

    // IKeyAgreementService state -- again a distinct key pair, never in use simultaneously with the
    // other two for the same instance. asymmetricModeIsKeyAgreement dispatches GenerateKeyPair()
    // and is checked before asymmetricModeIsSignature. P-256 keeps its private scalar as an MPI
    // (the low-level gcry_mpi_ec_* API works on MPIs); X25519 keeps a raw 32-byte scalar, which is
    // exactly what gcry_ecc_mul_point takes.
    bool asymmetricModeIsKeyAgreement;
    KeyAgreementAlgorithm keyAgreementAlgorithm;
    bool keyAgreementKeyGenerated;
    unsigned int keyAgreementPublicKeySize;
    unsigned int keyAgreementSharedSecretSize;
    gcry_mpi_t ecdhPrivateScalar;
    unsigned char x25519PrivateKey[32];
    std::vector<unsigned char> keyAgreementPublicKey;

    // IRandomSource state -- which explicit algorithm GenerateRandomBytes() below uses. Only
    // RANDOM_SYSTEM is ever stored here; the NIST SP 800-90A DRBG values are rejected outright by
    // SelectAlgorithm (see its comment).
    RandomAlgorithm randomAlgorithm;

    Impl()
        : symmetricSelected(false), legacySelected(false), cipherAlgorithm(0), cipherMode(0),
          keySize(0), ivOrNonceSize(0), tagSize(0), blockSize(0), legacyPadded(false),
          aeadIsCcm(false), aeadNeedsDecryptionTag(false),
          rsaKeyBits(0), rsaKeyGenerated(false), rsaPublicKey(nullptr), rsaPrivateKey(nullptr),
          hashAlgorithm(GCRY_MD_NONE), hashSize(0), hashHandle(nullptr),
          asymmetricModeIsSignature(false), signatureAlgorithm(SIGNATURE_ECDSA_P256_SHA256),
          signatureKeyGenerated(false), signatureSize(0), signaturePublicKey(nullptr),
          signaturePrivateKey(nullptr),
          asymmetricModeIsKeyAgreement(false), keyAgreementAlgorithm(KEYAGREEMENT_ECDH_P256),
          keyAgreementKeyGenerated(false), keyAgreementPublicKeySize(0),
          keyAgreementSharedSecretSize(0), ecdhPrivateScalar(nullptr),
          randomAlgorithm(RANDOM_SYSTEM)
    {
        std::memset(x25519PrivateKey, 0, sizeof(x25519PrivateKey));
    }
    // -----------------------------------------------------------------------------

    ~Impl()
    {
        if (rsaPublicKey != nullptr)
        {
            gcry_sexp_release(rsaPublicKey);
        }
        if (rsaPrivateKey != nullptr)
        {
            gcry_sexp_release(rsaPrivateKey);
        }
        if (hashHandle != nullptr)
        {
            gcry_md_close(hashHandle);
        }
        if (signaturePublicKey != nullptr)
        {
            gcry_sexp_release(signaturePublicKey);
        }
        if (signaturePrivateKey != nullptr)
        {
            gcry_sexp_release(signaturePrivateKey);
        }
        if (ecdhPrivateScalar != nullptr)
        {
            gcry_mpi_release(ecdhPrivateScalar);
        }
    }
    // -----------------------------------------------------------------------------

    void ReleaseSignatureKeys(void)
    {
        if (signaturePublicKey != nullptr)
        {
            gcry_sexp_release(signaturePublicKey);
            signaturePublicKey = nullptr;
        }
        if (signaturePrivateKey != nullptr)
        {
            gcry_sexp_release(signaturePrivateKey);
            signaturePrivateKey = nullptr;
        }
        signatureKeyGenerated = false;
        signatureSize = 0;
    }
    // -----------------------------------------------------------------------------

    void ReleaseRsaKeys(void)
    {
        if (rsaPublicKey != nullptr)
        {
            gcry_sexp_release(rsaPublicKey);
            rsaPublicKey = nullptr;
        }
        if (rsaPrivateKey != nullptr)
        {
            gcry_sexp_release(rsaPrivateKey);
            rsaPrivateKey = nullptr;
        }
        rsaKeyGenerated = false;
    }
    // -----------------------------------------------------------------------------

    void ReleaseKeyAgreementKeys(void)
    {
        if (ecdhPrivateScalar != nullptr)
        {
            gcry_mpi_release(ecdhPrivateScalar);
            ecdhPrivateScalar = nullptr;
        }
        std::memset(x25519PrivateKey, 0, sizeof(x25519PrivateKey));
        keyAgreementPublicKey.clear();
        keyAgreementKeyGenerated = false;
    }
    // -----------------------------------------------------------------------------
};

CLibgcryptProvider::~CLibgcryptProvider()
{
}
// -----------------------------------------------------------------------------

CLibgcryptProvider::CLibgcryptProvider() : impl_(new Impl())
{
    InitializeLibraryOnce();
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Initialize(void)
{
    try
    {
        return impl_ != nullptr && InitializeLibraryOnce();
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const AeadAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        AeadSpec spec;
        if (!AeadAlgorithmSpec(algorithm, &spec))
        {
            return false;
        }

        if (gcry_cipher_test_algo(spec.cipherAlgorithm) != 0)
        {
            return false;
        }

        impl_->symmetricSelected = true;
        impl_->legacySelected = false;
        impl_->cipherAlgorithm = spec.cipherAlgorithm;
        impl_->cipherMode = spec.cipherMode;
        impl_->keySize = spec.keySize;
        impl_->ivOrNonceSize = spec.nonceSize;
        impl_->tagSize = LIBGCRYPT_PROVIDER_TAG_SIZE;
        impl_->blockSize = static_cast<unsigned int>(gcry_cipher_get_algo_blklen(spec.cipherAlgorithm));
        impl_->legacyPadded = false;
        impl_->aeadIsCcm = (spec.cipherMode == GCRY_CIPHER_MODE_CCM);
        impl_->aeadNeedsDecryptionTag = (spec.cipherMode == GCRY_CIPHER_MODE_SIV ||
                                         spec.cipherMode == GCRY_CIPHER_MODE_GCM_SIV);
        impl_->key.assign(spec.keySize, 0);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        LegacySpec spec;
        if (!LegacyAlgorithmSpec(algorithm, &spec))
        {
            return false;
        }

        if (gcry_cipher_test_algo(spec.cipherAlgorithm) != 0)
        {
            return false;
        }

        const unsigned int blockSize = static_cast<unsigned int>(gcry_cipher_get_algo_blklen(spec.cipherAlgorithm));

        impl_->symmetricSelected = true;
        impl_->legacySelected = true;
        impl_->cipherAlgorithm = spec.cipherAlgorithm;
        impl_->cipherMode = spec.cipherMode;
        impl_->keySize = spec.keySize;
        impl_->ivOrNonceSize = spec.usesIv ? blockSize : 0;
        impl_->tagSize = 0;
        impl_->blockSize = blockSize;
        impl_->legacyPadded = spec.padded;
        impl_->aeadIsCcm = false;
        impl_->aeadNeedsDecryptionTag = false;
        impl_->key.assign(spec.keySize, 0);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetKeySize(void) const
{
    return impl_ ? impl_->keySize : 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (!impl_ || !impl_->symmetricSelected || key == nullptr || keySize != impl_->keySize)
        {
            return false;
        }

        impl_->key.assign(key, key + keySize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetNonceSize(void) const
{
    return (impl_ && !impl_->legacySelected) ? impl_->ivOrNonceSize : 0;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetTagSize(void) const
{
    return (impl_ && !impl_->legacySelected) ? impl_->tagSize : 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (!impl_ || !impl_->symmetricSelected || impl_->legacySelected || tag == nullptr ||
            tagSize != impl_->tagSize || nonce == nullptr || nonceSize != impl_->ivOrNonceSize ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        gcry_cipher_hd_t handle = nullptr;
        if (gcry_cipher_open(&handle, impl_->cipherAlgorithm, impl_->cipherMode, 0) != 0)
        {
            return false;
        }

        bool encrypted = false;
        do
        {
            if (gcry_cipher_setkey(handle, impl_->key.data(), impl_->keySize) != 0 ||
                gcry_cipher_setiv(handle, nonce, nonceSize) != 0)
            {
                break;
            }

            // CCM needs the exact plaintext/AAD/tag lengths declared up front, before any data is
            // processed; GCM/EAX/SIV/GCM-SIV/Poly1305 do not.
            if (impl_->aeadIsCcm)
            {
                unsigned long long lengths[3];
                lengths[0] = inputBufferSize;
                lengths[1] = 0;
                lengths[2] = tagSize;
                if (gcry_cipher_ctl(handle, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof(lengths)) != 0)
                {
                    break;
                }
            }

            if (inputBufferSize > 0 &&
                gcry_cipher_encrypt(handle, outputBuffer, inputBufferSize, inputBuffer, inputBufferSize) != 0)
            {
                break;
            }

            if (gcry_cipher_gettag(handle, tag, tagSize) != 0)
            {
                break;
            }

            encrypted = true;
        }
        while (false);

        gcry_cipher_close(handle);
        return encrypted;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Decrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, const unsigned char* tag, const unsigned int tagSize, unsigned char* outputBuffer)
{
    try
    {
        if (!impl_ || !impl_->symmetricSelected || impl_->legacySelected || tag == nullptr ||
            tagSize != impl_->tagSize || nonce == nullptr || nonceSize != impl_->ivOrNonceSize ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        gcry_cipher_hd_t handle = nullptr;
        if (gcry_cipher_open(&handle, impl_->cipherAlgorithm, impl_->cipherMode, 0) != 0)
        {
            return false;
        }

        bool decrypted = false;
        do
        {
            if (gcry_cipher_setkey(handle, impl_->key.data(), impl_->keySize) != 0 ||
                gcry_cipher_setiv(handle, nonce, nonceSize) != 0)
            {
                break;
            }

            if (impl_->aeadIsCcm)
            {
                unsigned long long lengths[3];
                lengths[0] = inputBufferSize;
                lengths[1] = 0;
                lengths[2] = tagSize;
                if (gcry_cipher_ctl(handle, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof(lengths)) != 0)
                {
                    break;
                }
            }

            // SIV and GCM-SIV are both "synthetic IV" constructions: the tag IS the IV, so
            // libgcrypt refuses to decrypt (GPG_ERR_INV_STATE) until it has been handed the tag
            // BEFORE the ciphertext, unlike GCM/CCM/EAX where checktag afterwards is enough.
            if (impl_->aeadNeedsDecryptionTag &&
                gcry_cipher_set_decryption_tag(handle, const_cast<unsigned char*>(tag), tagSize) != 0)
            {
                break;
            }

            if (inputBufferSize > 0 &&
                gcry_cipher_decrypt(handle, outputBuffer, inputBufferSize, inputBuffer, inputBufferSize) != 0)
            {
                break;
            }

            if (gcry_cipher_checktag(handle, tag, tagSize) != 0)
            {
                break;
            }

            decrypted = true;
        }
        while (false);

        gcry_cipher_close(handle);
        return decrypted;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetIvSize(void) const
{
    return (impl_ && impl_->legacySelected) ? impl_->ivOrNonceSize : 0;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetBlockSize(void) const
{
    return impl_ ? impl_->blockSize : 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Encrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->symmetricSelected || !impl_->legacySelected || outputBufferSize == nullptr)
        {
            return false;
        }
        if (impl_->ivOrNonceSize > 0 && (iv == nullptr || ivSize != impl_->ivOrNonceSize))
        {
            return false;
        }
        if (inputBufferSize > 0 && inputBuffer == nullptr)
        {
            return false;
        }

        // Same capacity convention as every other provider: block modes grow to the next whole
        // block (always at least one full PKCS#7 pad block, even when already aligned); stream-like
        // modes (CTR/CFB/OFB/RC4) produce exactly the plaintext length.
        const unsigned int required = impl_->legacyPadded
            ? ((inputBufferSize / impl_->blockSize) + 1) * impl_->blockSize
            : inputBufferSize;

        if (outputBufferCapacity == 0 || outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = required;
            return false;
        }

        if (inputBufferSize > 0)
        {
            std::memcpy(outputBuffer, inputBuffer, inputBufferSize);
        }

        // libgcrypt performs no padding of its own (unlike OpenSSL's EVP layer), so PKCS#7 is
        // applied here, in place, before the cipher runs over the whole padded block sequence.
        if (impl_->legacyPadded)
        {
            const unsigned int padSize = required - inputBufferSize;
            std::memset(outputBuffer + inputBufferSize, static_cast<int>(padSize), padSize);
        }

        if (required == 0)
        {
            *outputBufferSize = 0;
            return true;
        }

        gcry_cipher_hd_t handle = nullptr;
        if (gcry_cipher_open(&handle, impl_->cipherAlgorithm, impl_->cipherMode, 0) != 0)
        {
            return false;
        }

        bool encrypted = false;
        do
        {
            if (gcry_cipher_setkey(handle, impl_->key.data(), impl_->keySize) != 0)
            {
                break;
            }

            if (impl_->ivOrNonceSize > 0)
            {
                // CTR's "IV" is the initial counter block, which libgcrypt takes through its own
                // setctr entry point rather than setiv.
                const int status = (impl_->cipherMode == GCRY_CIPHER_MODE_CTR)
                    ? gcry_cipher_setctr(handle, iv, ivSize)
                    : gcry_cipher_setiv(handle, iv, ivSize);
                if (status != 0)
                {
                    break;
                }
            }

            if (gcry_cipher_encrypt(handle, outputBuffer, required, nullptr, 0) != 0)
            {
                break;
            }

            encrypted = true;
        }
        while (false);

        gcry_cipher_close(handle);
        if (!encrypted)
        {
            return false;
        }

        *outputBufferSize = required;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Decrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->symmetricSelected || !impl_->legacySelected || outputBufferSize == nullptr)
        {
            return false;
        }
        if (impl_->ivOrNonceSize > 0 && (iv == nullptr || ivSize != impl_->ivOrNonceSize))
        {
            return false;
        }
        if (inputBufferSize > 0 && inputBuffer == nullptr)
        {
            return false;
        }
        if (impl_->legacyPadded && (inputBufferSize == 0 || (inputBufferSize % impl_->blockSize) != 0))
        {
            return false;
        }

        const unsigned int required = inputBufferSize;
        if (outputBufferCapacity == 0 || outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = required;
            return false;
        }

        if (required == 0)
        {
            *outputBufferSize = 0;
            return true;
        }

        std::memcpy(outputBuffer, inputBuffer, inputBufferSize);

        gcry_cipher_hd_t handle = nullptr;
        if (gcry_cipher_open(&handle, impl_->cipherAlgorithm, impl_->cipherMode, 0) != 0)
        {
            return false;
        }

        bool decrypted = false;
        do
        {
            if (gcry_cipher_setkey(handle, impl_->key.data(), impl_->keySize) != 0)
            {
                break;
            }

            if (impl_->ivOrNonceSize > 0)
            {
                const int status = (impl_->cipherMode == GCRY_CIPHER_MODE_CTR)
                    ? gcry_cipher_setctr(handle, iv, ivSize)
                    : gcry_cipher_setiv(handle, iv, ivSize);
                if (status != 0)
                {
                    break;
                }
            }

            if (gcry_cipher_decrypt(handle, outputBuffer, inputBufferSize, nullptr, 0) != 0)
            {
                break;
            }

            decrypted = true;
        }
        while (false);

        gcry_cipher_close(handle);
        if (!decrypted)
        {
            return false;
        }

        unsigned int plaintextSize = inputBufferSize;
        if (impl_->legacyPadded)
        {
            // Strip (and validate) the PKCS#7 padding this provider added in Encrypt above.
            const unsigned int padSize = outputBuffer[inputBufferSize - 1];
            if (padSize == 0 || padSize > impl_->blockSize || padSize > inputBufferSize)
            {
                return false;
            }
            for (unsigned int index = 0; index < padSize; ++index)
            {
                if (outputBuffer[inputBufferSize - 1 - index] != static_cast<unsigned char>(padSize))
                {
                    return false;
                }
            }
            plaintextSize = inputBufferSize - padSize;
        }

        *outputBufferSize = plaintextSize;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::DerivePasswordKey(const char* password, const unsigned int passwordSize, const unsigned char* salt, const unsigned int saltSize, const unsigned int iterationCount, unsigned char* derivedKey, const unsigned int derivedKeySize)
{
    try
    {
        if (password == nullptr || salt == nullptr || derivedKey == nullptr || derivedKeySize == 0)
        {
            return false;
        }

        return gcry_kdf_derive(password, passwordSize,
                               GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
                               salt, saltSize,
                               iterationCount,
                               derivedKeySize, derivedKey) == 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const RandomAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        // libgcrypt's public RNG surface exposes entropy LEVELS (GCRY_WEAK_RANDOM /
        // GCRY_STRONG_RANDOM / GCRY_VERY_STRONG_RANDOM), not separately selectable NIST SP 800-90A
        // DRBG mechanisms: its internal FIPS DRBG is process-global, reachable only through
        // GCRYCTL_DRBG_REINIT, and not choosable per random source. So RANDOM_HASH_DRBG /
        // RANDOM_HMAC_DRBG / RANDOM_CTR_DRBG are honestly reported unsupported here rather than
        // silently aliased to the system RNG -- the same reasoning as RANDOM_CTR_DRBG on
        // PROVIDER_MICROSOFT (see RandomAlgorithm's doc comment in ProviderTypes.h).
        if (algorithm != RANDOM_SYSTEM)
        {
            return false;
        }

        impl_->randomAlgorithm = algorithm;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize)
{
    try
    {
        if (!impl_ || !InitializeLibraryOnce() || (buffer == nullptr && bufferSize > 0))
        {
            return false;
        }

        if (bufferSize == 0)
        {
            return true;
        }

        gcry_randomize(buffer, bufferSize, GCRY_STRONG_RANDOM);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const AsymmetricAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        const unsigned int keyBits = AsymmetricKeyBits(algorithm);
        if (keyBits == 0)
        {
            return false;
        }

        impl_->rsaKeyBits = keyBits;
        impl_->ReleaseRsaKeys();
        impl_->asymmetricModeIsSignature = false;
        impl_->asymmetricModeIsKeyAgreement = false;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::GenerateKeyPair(void)
{
    try
    {
        if (!impl_ || !InitializeLibraryOnce())
        {
            return false;
        }

        if (impl_->asymmetricModeIsKeyAgreement)
        {
            const unsigned int publicKeySize = KeyAgreementPublicKeySize(impl_->keyAgreementAlgorithm);
            const unsigned int sharedSecretSize = KeyAgreementSharedSecretSize(impl_->keyAgreementAlgorithm);
            if (publicKeySize == 0 || sharedSecretSize == 0)
            {
                return false;
            }

            impl_->ReleaseKeyAgreementKeys();

            if (impl_->keyAgreementAlgorithm == KEYAGREEMENT_X25519)
            {
                // RFC 7748 X25519: the private key is simply 32 random bytes (gcry_ecc_mul_point
                // applies the mandatory clamping internally), and the public key is that scalar
                // multiplied by the base point -- which gcry_ecc_mul_point selects by taking a
                // NULL point argument.
                unsigned char privateKey[32];
                gcry_randomize(privateKey, sizeof(privateKey), GCRY_VERY_STRONG_RANDOM);

                std::vector<unsigned char> publicKey(publicKeySize, 0);
                if (gcry_ecc_mul_point(GCRY_ECC_CURVE25519, publicKey.data(), privateKey, nullptr) != 0)
                {
                    std::memset(privateKey, 0, sizeof(privateKey));
                    return false;
                }

                std::memcpy(impl_->x25519PrivateKey, privateKey, sizeof(privateKey));
                std::memset(privateKey, 0, sizeof(privateKey));
                impl_->keyAgreementPublicKey.swap(publicKey);
            }
            else
            {
                // ECDH P-256: let libgcrypt's own ECC key generator produce a valid (d, Q) pair,
                // then keep d as an MPI for the low-level gcry_mpi_ec_* multiplication in
                // DeriveSharedSecret and Q as the SEC1 uncompressed point this SDK exports.
                gcry_sexp_t parameters = nullptr;
                if (gcry_sexp_build(&parameters, nullptr, "(genkey (ecc (curve %s)))", "NIST P-256") != 0)
                {
                    return false;
                }

                gcry_sexp_t keyPair = nullptr;
                const int generateStatus = gcry_pk_genkey(&keyPair, parameters);
                gcry_sexp_release(parameters);
                if (generateStatus != 0)
                {
                    return false;
                }

                gcry_sexp_t privatePart = gcry_sexp_find_token(keyPair, "private-key", 0);
                gcry_sexp_t publicPart = gcry_sexp_find_token(keyPair, "public-key", 0);
                std::vector<unsigned char> publicKey(publicKeySize, 0);
                gcry_mpi_t privateScalar = nullptr;

                bool extracted = false;
                if (privatePart != nullptr && publicPart != nullptr)
                {
                    gcry_sexp_t scalarElement = gcry_sexp_find_token(privatePart, "d", 0);
                    if (scalarElement != nullptr)
                    {
                        privateScalar = gcry_sexp_nth_mpi(scalarElement, 1, GCRYMPI_FMT_USG);
                        gcry_sexp_release(scalarElement);
                    }
                    extracted = (privateScalar != nullptr) &&
                                SexpTokenToFixedBuffer(publicPart, "q", publicKey.data(), publicKeySize);
                }

                if (privatePart != nullptr)
                {
                    gcry_sexp_release(privatePart);
                }
                if (publicPart != nullptr)
                {
                    gcry_sexp_release(publicPart);
                }
                gcry_sexp_release(keyPair);

                if (!extracted)
                {
                    if (privateScalar != nullptr)
                    {
                        gcry_mpi_release(privateScalar);
                    }
                    return false;
                }

                impl_->ecdhPrivateScalar = privateScalar;
                impl_->keyAgreementPublicKey.swap(publicKey);
            }

            impl_->keyAgreementPublicKeySize = publicKeySize;
            impl_->keyAgreementSharedSecretSize = sharedSecretSize;
            impl_->keyAgreementKeyGenerated = true;
            return true;
        }

        if (impl_->asymmetricModeIsSignature)
        {
            const unsigned int rsaKeyBits = SignatureRsaKeyBits(impl_->signatureAlgorithm);
            const unsigned int dsaParamBits = SignatureDsaParamBits(impl_->signatureAlgorithm);
            const unsigned int ecdsaComponentBytes = SignatureEcdsaComponentBytes(impl_->signatureAlgorithm);
            const char* curveName = SignatureCurveName(impl_->signatureAlgorithm);

            gcry_sexp_t parameters = nullptr;
            int buildStatus = 0;

            if (rsaKeyBits != 0)
            {
                buildStatus = gcry_sexp_build(&parameters, nullptr, "(genkey (rsa (nbits %d)))",
                                              static_cast<int>(rsaKeyBits));
            }
            else if (dsaParamBits != 0)
            {
                // N (qbits) is pinned to 256 at both L values so the raw r||s signature stays a
                // fixed 64 bytes, matching this SDK's fixed-per-algorithm size promise.
                buildStatus = gcry_sexp_build(&parameters, nullptr, "(genkey (dsa (nbits %d) (qbits %d)))",
                                              static_cast<int>(dsaParamBits), 256);
            }
            else if (impl_->signatureAlgorithm == SIGNATURE_ED25519)
            {
                buildStatus = gcry_sexp_build(&parameters, nullptr, "(genkey (ecc (curve %s) (flags eddsa)))",
                                              curveName);
            }
            else if (ecdsaComponentBytes != 0 && curveName != nullptr)
            {
                buildStatus = gcry_sexp_build(&parameters, nullptr, "(genkey (ecc (curve %s)))", curveName);
            }
            else
            {
                return false;
            }

            if (buildStatus != 0)
            {
                return false;
            }

            gcry_sexp_t keyPair = nullptr;
            const int generateStatus = gcry_pk_genkey(&keyPair, parameters);
            gcry_sexp_release(parameters);
            if (generateStatus != 0)
            {
                return false;
            }

            gcry_sexp_t publicPart = gcry_sexp_find_token(keyPair, "public-key", 0);
            gcry_sexp_t privatePart = gcry_sexp_find_token(keyPair, "private-key", 0);
            gcry_sexp_release(keyPair);

            if (publicPart == nullptr || privatePart == nullptr)
            {
                if (publicPart != nullptr)
                {
                    gcry_sexp_release(publicPart);
                }
                if (privatePart != nullptr)
                {
                    gcry_sexp_release(privatePart);
                }
                return false;
            }

            impl_->ReleaseSignatureKeys();
            impl_->signaturePublicKey = publicPart;
            impl_->signaturePrivateKey = privatePart;

            if (rsaKeyBits != 0)
            {
                impl_->signatureSize = rsaKeyBits / 8; // RSA-PSS: one integer, modulus-sized
            }
            else if (dsaParamBits != 0)
            {
                impl_->signatureSize = 64;             // DSA: 32-byte r + 32-byte s (N = 256 bits)
            }
            else if (impl_->signatureAlgorithm == SIGNATURE_ED25519)
            {
                impl_->signatureSize = 64;             // Ed25519: 32-byte R + 32-byte S
            }
            else
            {
                impl_->signatureSize = 2u * ecdsaComponentBytes; // ECDSA: raw r||s
            }

            impl_->signatureKeyGenerated = true;
            return true;
        }

        if (impl_->rsaKeyBits == 0)
        {
            return false;
        }

        gcry_sexp_t parameters = nullptr;
        if (gcry_sexp_build(&parameters, nullptr, "(genkey (rsa (nbits %d)))",
                            static_cast<int>(impl_->rsaKeyBits)) != 0)
        {
            return false;
        }

        gcry_sexp_t keyPair = nullptr;
        const int generateStatus = gcry_pk_genkey(&keyPair, parameters);
        gcry_sexp_release(parameters);
        if (generateStatus != 0)
        {
            return false;
        }

        gcry_sexp_t publicPart = gcry_sexp_find_token(keyPair, "public-key", 0);
        gcry_sexp_t privatePart = gcry_sexp_find_token(keyPair, "private-key", 0);
        gcry_sexp_release(keyPair);

        if (publicPart == nullptr || privatePart == nullptr)
        {
            if (publicPart != nullptr)
            {
                gcry_sexp_release(publicPart);
            }
            if (privatePart != nullptr)
            {
                gcry_sexp_release(privatePart);
            }
            return false;
        }

        impl_->ReleaseRsaKeys();
        impl_->rsaPublicKey = publicPart;
        impl_->rsaPrivateKey = privatePart;
        impl_->rsaKeyGenerated = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetMaxPlaintextSize(void) const
{
    try
    {
        if (!impl_ || !impl_->rsaKeyGenerated)
        {
            return 0;
        }

        const unsigned int keyBytes = impl_->rsaKeyBits / 8;
        const unsigned int oaepOverhead = 2u * 32u + 2u; // SHA-256 OAEP: 2*hashLen + 2
        return keyBytes > oaepOverhead ? keyBytes - oaepOverhead : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetCiphertextSize(void) const
{
    try
    {
        return (impl_ && impl_->rsaKeyGenerated) ? impl_->rsaKeyBits / 8 : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Encrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->rsaKeyGenerated || impl_->rsaPublicKey == nullptr ||
            outputBufferSize == nullptr || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        const unsigned int required = impl_->rsaKeyBits / 8;
        if (outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = required;
            return false;
        }

        gcry_sexp_t plainSexp = nullptr;
        if (gcry_sexp_build(&plainSexp, nullptr, "(data (flags oaep) (hash-algo sha256) (value %b))",
                            static_cast<int>(inputBufferSize),
                            reinterpret_cast<const char*>(inputBuffer)) != 0)
        {
            return false;
        }

        gcry_sexp_t cipherSexp = nullptr;
        const int encryptStatus = gcry_pk_encrypt(&cipherSexp, plainSexp, impl_->rsaPublicKey);
        gcry_sexp_release(plainSexp);
        if (encryptStatus != 0)
        {
            return false;
        }

        const bool extracted = SexpTokenToFixedBuffer(cipherSexp, "a", outputBuffer, required);
        gcry_sexp_release(cipherSexp);
        if (!extracted)
        {
            return false;
        }

        *outputBufferSize = required;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Decrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->rsaKeyGenerated || impl_->rsaPrivateKey == nullptr ||
            outputBufferSize == nullptr || inputBuffer == nullptr ||
            inputBufferSize != impl_->rsaKeyBits / 8)
        {
            return false;
        }

        // libgcrypt quirk: the enc-val S-expression gcry_pk_encrypt hands back does NOT carry the
        // (flags oaep)/(hash-algo ...) it was given, and gcry_pk_decrypt would then silently return
        // the raw, still-padded block instead of failing. So the enc-val is rebuilt here with the
        // padding scheme spelled out explicitly -- which is also exactly what a caller decrypting
        // ciphertext that arrived from elsewhere has to do.
        gcry_sexp_t cipherSexp = nullptr;
        if (gcry_sexp_build(&cipherSexp, nullptr,
                            "(enc-val (flags oaep) (hash-algo sha256) (rsa (a %b)))",
                            static_cast<int>(inputBufferSize),
                            reinterpret_cast<const char*>(inputBuffer)) != 0)
        {
            return false;
        }

        gcry_sexp_t plainSexp = nullptr;
        const int decryptStatus = gcry_pk_decrypt(&plainSexp, cipherSexp, impl_->rsaPrivateKey);
        gcry_sexp_release(cipherSexp);
        if (decryptStatus != 0)
        {
            return false;
        }

        // With an explicit padding flag the result is "(value <plaintext>)", so the plaintext is
        // element 1, not element 0.
        std::size_t plainSize = 0;
        const char* plainData = gcry_sexp_nth_data(plainSexp, 1, &plainSize);
        if (plainData == nullptr)
        {
            gcry_sexp_release(plainSexp);
            return false;
        }

        const unsigned int required = static_cast<unsigned int>(plainSize);
        if (outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = required;
            gcry_sexp_release(plainSexp);
            return false;
        }

        if (required > 0)
        {
            std::memcpy(outputBuffer, plainData, required);
        }
        gcry_sexp_release(plainSexp);

        *outputBufferSize = required;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetMacSize(void) const
{
    return 32; // HMAC-SHA256
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::ComputeMac(const unsigned char* key, const unsigned int keySize, const unsigned char* data, const unsigned int dataSize, unsigned char* mac, const unsigned int macSize)
{
    try
    {
        if (!InitializeLibraryOnce() || key == nullptr || keySize == 0 || mac == nullptr ||
            macSize != 32 || (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        gcry_mac_hd_t handle = nullptr;
        if (gcry_mac_open(&handle, GCRY_MAC_HMAC_SHA256, 0, nullptr) != 0)
        {
            return false;
        }

        bool computed = false;
        do
        {
            if (gcry_mac_setkey(handle, key, keySize) != 0)
            {
                break;
            }

            if (dataSize > 0 && gcry_mac_write(handle, data, dataSize) != 0)
            {
                break;
            }

            std::size_t actualSize = macSize;
            if (gcry_mac_read(handle, mac, &actualSize) != 0 || actualSize != macSize)
            {
                break;
            }

            computed = true;
        }
        while (false);

        gcry_mac_close(handle);
        return computed;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const HashAlgorithm algorithm)
{
    try
    {
        if (!impl_ || !InitializeLibraryOnce())
        {
            return false;
        }

        const int hashAlgorithm = HashAlgorithmId(algorithm);
        if (hashAlgorithm == GCRY_MD_NONE || gcry_md_test_algo(hashAlgorithm) != 0)
        {
            return false;
        }

        gcry_md_hd_t handle = nullptr;
        if (gcry_md_open(&handle, hashAlgorithm, 0) != 0)
        {
            return false;
        }

        if (impl_->hashHandle != nullptr)
        {
            gcry_md_close(impl_->hashHandle);
        }

        impl_->hashHandle = handle;
        impl_->hashAlgorithm = hashAlgorithm;
        impl_->hashSize = gcry_md_get_algo_dlen(hashAlgorithm);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetHashSize(void) const
{
    return impl_ ? impl_->hashSize : 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::ComputeHash(const unsigned char* data, const unsigned int dataSize, unsigned char* hash, const unsigned int hashSize)
{
    return Init() && Update(data, dataSize) && Final(hash, hashSize);
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Init(void)
{
    try
    {
        if (!impl_ || impl_->hashHandle == nullptr)
        {
            return false;
        }

        gcry_md_reset(impl_->hashHandle);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Update(const unsigned char* data, const unsigned int dataSize)
{
    try
    {
        if (!impl_ || impl_->hashHandle == nullptr || (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        if (dataSize == 0)
        {
            return true;
        }

        gcry_md_write(impl_->hashHandle, data, dataSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Final(unsigned char* hash, const unsigned int hashSize)
{
    try
    {
        if (!impl_ || impl_->hashHandle == nullptr || hash == nullptr || impl_->hashSize == 0 ||
            hashSize < impl_->hashSize)
        {
            return false;
        }

        // gcry_md_read finalizes the digest in progress and returns a pointer into libgcrypt's own
        // handle-owned buffer (not a copy the caller has to free).
        const unsigned char* digest = gcry_md_read(impl_->hashHandle, impl_->hashAlgorithm);
        if (digest == nullptr)
        {
            return false;
        }

        std::memcpy(hash, digest, impl_->hashSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const SignatureAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        switch (algorithm)
        {
            case SIGNATURE_RSA_PSS_SHA256_2048:
            case SIGNATURE_RSA_PSS_SHA256_3072:
            case SIGNATURE_RSA_PSS_SHA256_4096:
            case SIGNATURE_ECDSA_P256_SHA256:
            case SIGNATURE_ECDSA_P384_SHA384:
            case SIGNATURE_ECDSA_P521_SHA512:
            case SIGNATURE_DSA_SHA256_2048:
            case SIGNATURE_DSA_SHA256_3072:
            case SIGNATURE_ED25519:
                break;
            default:
                return false;
        }

        impl_->signatureAlgorithm = algorithm;
        impl_->ReleaseSignatureKeys();
        impl_->asymmetricModeIsSignature = true;
        impl_->asymmetricModeIsKeyAgreement = false;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetSignatureSize(void) const
{
    return (impl_ && impl_->signatureKeyGenerated) ? impl_->signatureSize : 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Sign(const unsigned char* data, const unsigned int dataSize, unsigned char* signature, const unsigned int signatureSize)
{
    try
    {
        if (!impl_ || !impl_->signatureKeyGenerated || impl_->signaturePrivateKey == nullptr ||
            signature == nullptr || signatureSize < impl_->signatureSize ||
            (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        gcry_sexp_t dataSexp = BuildSignatureDataSexp(impl_->signatureAlgorithm, data, dataSize);
        if (dataSexp == nullptr)
        {
            return false;
        }

        gcry_sexp_t signatureSexp = nullptr;
        const int signStatus = gcry_pk_sign(&signatureSexp, dataSexp, impl_->signaturePrivateKey);
        gcry_sexp_release(dataSexp);
        if (signStatus != 0)
        {
            return false;
        }

        bool extracted = false;
        const unsigned int ecdsaComponentBytes = SignatureEcdsaComponentBytes(impl_->signatureAlgorithm);

        if (SignatureRsaKeyBits(impl_->signatureAlgorithm) != 0)
        {
            extracted = SexpTokenToFixedBuffer(signatureSexp, "s", signature, impl_->signatureSize);
        }
        else if (impl_->signatureAlgorithm == SIGNATURE_ED25519)
        {
            extracted = SexpTokenToRawBuffer(signatureSexp, "r", signature, 32) &&
                        SexpTokenToRawBuffer(signatureSexp, "s", signature + 32, 32);
        }
        else if (ecdsaComponentBytes != 0)
        {
            extracted = SexpTokenToFixedBuffer(signatureSexp, "r", signature, ecdsaComponentBytes) &&
                        SexpTokenToFixedBuffer(signatureSexp, "s", signature + ecdsaComponentBytes, ecdsaComponentBytes);
        }
        else if (SignatureDsaParamBits(impl_->signatureAlgorithm) != 0)
        {
            extracted = SexpTokenToFixedBuffer(signatureSexp, "r", signature, 32) &&
                        SexpTokenToFixedBuffer(signatureSexp, "s", signature + 32, 32);
        }

        gcry_sexp_release(signatureSexp);
        return extracted;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Verify(const unsigned char* data, const unsigned int dataSize, const unsigned char* signature, const unsigned int signatureSize)
{
    try
    {
        if (!impl_ || !impl_->signatureKeyGenerated || impl_->signaturePublicKey == nullptr ||
            signature == nullptr || signatureSize != impl_->signatureSize ||
            (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        gcry_sexp_t dataSexp = BuildSignatureDataSexp(impl_->signatureAlgorithm, data, dataSize);
        if (dataSexp == nullptr)
        {
            return false;
        }

        // Rebuild libgcrypt's own sig-val shape from this SDK's fixed raw wire format (one
        // modulus-sized integer for RSA-PSS, r||s for ECDSA/EdDSA/DSA).
        gcry_sexp_t signatureSexp = nullptr;
        int buildStatus = 0;
        const unsigned int ecdsaComponentBytes = SignatureEcdsaComponentBytes(impl_->signatureAlgorithm);

        if (SignatureRsaKeyBits(impl_->signatureAlgorithm) != 0)
        {
            buildStatus = gcry_sexp_build(&signatureSexp, nullptr, "(sig-val (rsa (s %b)))",
                                          static_cast<int>(signatureSize),
                                          reinterpret_cast<const char*>(signature));
        }
        else if (impl_->signatureAlgorithm == SIGNATURE_ED25519)
        {
            buildStatus = gcry_sexp_build(&signatureSexp, nullptr, "(sig-val (eddsa (r %b) (s %b)))",
                                          32, reinterpret_cast<const char*>(signature),
                                          32, reinterpret_cast<const char*>(signature + 32));
        }
        else if (ecdsaComponentBytes != 0)
        {
            buildStatus = gcry_sexp_build(&signatureSexp, nullptr, "(sig-val (ecdsa (r %b) (s %b)))",
                                          static_cast<int>(ecdsaComponentBytes), reinterpret_cast<const char*>(signature),
                                          static_cast<int>(ecdsaComponentBytes), reinterpret_cast<const char*>(signature + ecdsaComponentBytes));
        }
        else if (SignatureDsaParamBits(impl_->signatureAlgorithm) != 0)
        {
            buildStatus = gcry_sexp_build(&signatureSexp, nullptr, "(sig-val (dsa (r %b) (s %b)))",
                                          32, reinterpret_cast<const char*>(signature),
                                          32, reinterpret_cast<const char*>(signature + 32));
        }
        else
        {
            gcry_sexp_release(dataSexp);
            return false;
        }

        if (buildStatus != 0)
        {
            gcry_sexp_release(dataSexp);
            return false;
        }

        const int verifyStatus = gcry_pk_verify(signatureSexp, dataSexp, impl_->signaturePublicKey);
        gcry_sexp_release(signatureSexp);
        gcry_sexp_release(dataSexp);
        return verifyStatus == 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const KeyAgreementAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        switch (algorithm)
        {
            case KEYAGREEMENT_ECDH_P256:
            case KEYAGREEMENT_X25519:
                break;
            default:
                return false;
        }

        impl_->keyAgreementAlgorithm = algorithm;
        impl_->ReleaseKeyAgreementKeys();
        impl_->keyAgreementPublicKeySize = 0;
        impl_->keyAgreementSharedSecretSize = 0;
        impl_->asymmetricModeIsKeyAgreement = true;
        impl_->asymmetricModeIsSignature = false;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetPublicKeySize(void) const
{
    return (impl_ && impl_->keyAgreementKeyGenerated) ? impl_->keyAgreementPublicKeySize : 0;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetSharedSecretSize(void) const
{
    return (impl_ && impl_->keyAgreementKeyGenerated) ? impl_->keyAgreementSharedSecretSize : 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::GetPublicKey(unsigned char* publicKey, const unsigned int publicKeySize) const
{
    try
    {
        if (!impl_ || !impl_->keyAgreementKeyGenerated || publicKey == nullptr ||
            publicKeySize < impl_->keyAgreementPublicKeySize ||
            impl_->keyAgreementPublicKey.size() != impl_->keyAgreementPublicKeySize)
        {
            return false;
        }

        std::memcpy(publicKey, impl_->keyAgreementPublicKey.data(), impl_->keyAgreementPublicKeySize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::DeriveSharedSecret(const unsigned char* peerPublicKey, const unsigned int peerPublicKeySize, unsigned char* sharedSecret, const unsigned int sharedSecretSize)
{
    try
    {
        if (!impl_ || !impl_->keyAgreementKeyGenerated || peerPublicKey == nullptr ||
            peerPublicKeySize != impl_->keyAgreementPublicKeySize || sharedSecret == nullptr ||
            sharedSecretSize < impl_->keyAgreementSharedSecretSize)
        {
            return false;
        }

        if (impl_->keyAgreementAlgorithm == KEYAGREEMENT_X25519)
        {
            // RFC 7748 X25519 in one call: scalar * peer point, clamping applied internally.
            return gcry_ecc_mul_point(GCRY_ECC_CURVE25519, sharedSecret,
                                      impl_->x25519PrivateKey, peerPublicKey) == 0;
        }

        if (impl_->ecdhPrivateScalar == nullptr)
        {
            return false;
        }

        // ECDH P-256 through libgcrypt's low-level EC arithmetic API. libgcrypt's gcry_pk_encrypt
        // "ecdh" path is an ephemeral-key ECIES-style construction, not the static-static
        // Diffie-Hellman two-party agreement IKeyAgreementService models, so the point
        // multiplication is done directly here instead.
        gcry_ctx_t curveContext = nullptr;
        if (gcry_mpi_ec_new(&curveContext, nullptr, "NIST P-256") != 0)
        {
            return false;
        }

        gcry_mpi_t peerPointValue = nullptr;
        gcry_mpi_point_t peerPoint = nullptr;
        gcry_mpi_point_t sharedPoint = nullptr;
        gcry_mpi_t affineX = nullptr;
        gcry_mpi_t affineY = nullptr;
        bool derived = false;

        do
        {
            if (gcry_mpi_scan(&peerPointValue, GCRYMPI_FMT_USG, peerPublicKey, peerPublicKeySize, nullptr) != 0)
            {
                break;
            }

            peerPoint = gcry_mpi_point_new(0);
            if (peerPoint == nullptr || gcry_mpi_ec_decode_point(peerPoint, peerPointValue, curveContext) != 0)
            {
                break;
            }

            // Reject a peer public key that is not actually on the curve rather than deriving a
            // secret from a bogus point (invalid-curve attacks).
            if (!gcry_mpi_ec_curve_point(peerPoint, curveContext))
            {
                break;
            }

            sharedPoint = gcry_mpi_point_new(0);
            if (sharedPoint == nullptr)
            {
                break;
            }

            gcry_mpi_ec_mul(sharedPoint, impl_->ecdhPrivateScalar, peerPoint, curveContext);

            affineX = gcry_mpi_new(0);
            affineY = gcry_mpi_new(0);
            if (affineX == nullptr || affineY == nullptr ||
                gcry_mpi_ec_get_affine(affineX, affineY, sharedPoint, curveContext) != 0)
            {
                break;
            }

            derived = MpiToFixedBuffer(affineX, sharedSecret, impl_->keyAgreementSharedSecretSize);
        }
        while (false);

        if (peerPointValue != nullptr)
        {
            gcry_mpi_release(peerPointValue);
        }
        if (affineX != nullptr)
        {
            gcry_mpi_release(affineX);
        }
        if (affineY != nullptr)
        {
            gcry_mpi_release(affineY);
        }
        if (peerPoint != nullptr)
        {
            gcry_mpi_point_release(peerPoint);
        }
        if (sharedPoint != nullptr)
        {
            gcry_mpi_point_release(sharedPoint);
        }
        gcry_ctx_release(curveContext);

        return derived;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#else // CRYPTOAPI_LIBGCRYPT_AVAILABLE

// ================================================================================================
// Win32 (ARCH_X86/ARCH_WIN32) build: no libgcrypt binary exists for x86, so nothing below touches
// libgcrypt at all and every capability query / operation reports "unsupported" -- false, or 0 for
// the size queries. CCryptoApi/the Factory then behave exactly as they already do for any other
// provider/algorithm combination a provider does not implement (CMicrosoftProvider's
// SIGNATURE_ED25519, CBotanProvider's LEGACY_*_ECB, and so on): cleanly rejected, never silently
// wrong output. The class keeps the identical shape so Win32 and x64 share one header and one
// registration path.
// ================================================================================================

namespace CryptoApiNS
{

struct CLibgcryptProvider::Impl
{
};

CLibgcryptProvider::~CLibgcryptProvider()
{
}
// -----------------------------------------------------------------------------

CLibgcryptProvider::CLibgcryptProvider() : impl_(new Impl())
{
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Initialize(void)
{
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const AeadAlgorithm algorithm)
{
    (void)algorithm;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const LegacySymmetricAlgorithm algorithm)
{
    (void)algorithm;
    return false;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetKeySize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    (void)key;
    (void)keySize;
    return false;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetNonceSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetTagSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, unsigned char* tag, const unsigned int tagSize)
{
    (void)nonce;
    (void)nonceSize;
    (void)inputBuffer;
    (void)inputBufferSize;
    (void)outputBuffer;
    (void)tag;
    (void)tagSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Decrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, const unsigned char* tag, const unsigned int tagSize, unsigned char* outputBuffer)
{
    (void)nonce;
    (void)nonceSize;
    (void)inputBuffer;
    (void)inputBufferSize;
    (void)tag;
    (void)tagSize;
    (void)outputBuffer;
    return false;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetIvSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetBlockSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Encrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    (void)iv;
    (void)ivSize;
    (void)inputBuffer;
    (void)inputBufferSize;
    (void)outputBuffer;
    (void)outputBufferCapacity;
    (void)outputBufferSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Decrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    (void)iv;
    (void)ivSize;
    (void)inputBuffer;
    (void)inputBufferSize;
    (void)outputBuffer;
    (void)outputBufferCapacity;
    (void)outputBufferSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::DerivePasswordKey(const char* password, const unsigned int passwordSize, const unsigned char* salt, const unsigned int saltSize, const unsigned int iterationCount, unsigned char* derivedKey, const unsigned int derivedKeySize)
{
    (void)password;
    (void)passwordSize;
    (void)salt;
    (void)saltSize;
    (void)iterationCount;
    (void)derivedKey;
    (void)derivedKeySize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const RandomAlgorithm algorithm)
{
    (void)algorithm;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize)
{
    (void)buffer;
    (void)bufferSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const AsymmetricAlgorithm algorithm)
{
    (void)algorithm;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::GenerateKeyPair(void)
{
    return false;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetMaxPlaintextSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetCiphertextSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Encrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    (void)inputBuffer;
    (void)inputBufferSize;
    (void)outputBuffer;
    (void)outputBufferCapacity;
    (void)outputBufferSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Decrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    (void)inputBuffer;
    (void)inputBufferSize;
    (void)outputBuffer;
    (void)outputBufferCapacity;
    (void)outputBufferSize;
    return false;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetMacSize(void) const
{
    return 32; // HMAC-SHA256 -- the size is a constant of the algorithm, not of the backing library
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::ComputeMac(const unsigned char* key, const unsigned int keySize, const unsigned char* data, const unsigned int dataSize, unsigned char* mac, const unsigned int macSize)
{
    (void)key;
    (void)keySize;
    (void)data;
    (void)dataSize;
    (void)mac;
    (void)macSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const HashAlgorithm algorithm)
{
    (void)algorithm;
    return false;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetHashSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::ComputeHash(const unsigned char* data, const unsigned int dataSize, unsigned char* hash, const unsigned int hashSize)
{
    (void)data;
    (void)dataSize;
    (void)hash;
    (void)hashSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Init(void)
{
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Update(const unsigned char* data, const unsigned int dataSize)
{
    (void)data;
    (void)dataSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Final(unsigned char* hash, const unsigned int hashSize)
{
    (void)hash;
    (void)hashSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const SignatureAlgorithm algorithm)
{
    (void)algorithm;
    return false;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetSignatureSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Sign(const unsigned char* data, const unsigned int dataSize, unsigned char* signature, const unsigned int signatureSize)
{
    (void)data;
    (void)dataSize;
    (void)signature;
    (void)signatureSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::Verify(const unsigned char* data, const unsigned int dataSize, const unsigned char* signature, const unsigned int signatureSize)
{
    (void)data;
    (void)dataSize;
    (void)signature;
    (void)signatureSize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::SelectAlgorithm(const KeyAgreementAlgorithm algorithm)
{
    (void)algorithm;
    return false;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetPublicKeySize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

unsigned int CLibgcryptProvider::GetSharedSecretSize(void) const
{
    return 0;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::GetPublicKey(unsigned char* publicKey, const unsigned int publicKeySize) const
{
    (void)publicKey;
    (void)publicKeySize;
    return false;
}
// -----------------------------------------------------------------------------

bool CLibgcryptProvider::DeriveSharedSecret(const unsigned char* peerPublicKey, const unsigned int peerPublicKeySize, unsigned char* sharedSecret, const unsigned int sharedSecretSize)
{
    (void)peerPublicKey;
    (void)peerPublicKeySize;
    (void)sharedSecret;
    (void)sharedSecretSize;
    return false;
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#endif // CRYPTOAPI_LIBGCRYPT_AVAILABLE

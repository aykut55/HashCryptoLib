#include "OpenSslProvider.h"

#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"

#include <cstring>
#include <vector>

namespace CryptoApiNS
{

namespace
{
    const unsigned int OPENSSL_PROVIDER_TAG_SIZE = 16;

    const char* AeadCipherName(const AeadAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case AEAD_AES_128_GCM: return "AES-128-GCM";
        case AEAD_AES_192_GCM: return "AES-192-GCM";
        case AEAD_AES_256_GCM: return "AES-256-GCM";
        case AEAD_AES_128_CCM: return "AES-128-CCM";
        case AEAD_AES_192_CCM: return "AES-192-CCM";
        case AEAD_AES_256_CCM: return "AES-256-CCM";
        case AEAD_CHACHA20_POLY1305: return "ChaCha20-Poly1305";
        case AEAD_AES_128_SIV: return "AES-128-SIV";
        case AEAD_AES_256_SIV: return "AES-256-SIV";
        default:
            // EAX / AES-GCM-SIV / Twofish-GCM / Serpent-GCM / Camellia-GCM never existed in OpenSSL.
            return nullptr;
        }
    }
    // -----------------------------------------------------------------------------

    bool IsCcmAlgorithm(const AeadAlgorithm algorithm)
    {
        return algorithm == AEAD_AES_128_CCM || algorithm == AEAD_AES_192_CCM || algorithm == AEAD_AES_256_CCM;
    }
    // -----------------------------------------------------------------------------

    const char* LegacyCipherName(const LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case LEGACY_AES_128_CBC: return "AES-128-CBC";
        case LEGACY_AES_192_CBC: return "AES-192-CBC";
        case LEGACY_AES_256_CBC: return "AES-256-CBC";
        case LEGACY_AES_128_CTR: return "AES-128-CTR";
        case LEGACY_AES_192_CTR: return "AES-192-CTR";
        case LEGACY_AES_256_CTR: return "AES-256-CTR";
        case LEGACY_AES_128_CFB: return "AES-128-CFB";
        case LEGACY_AES_192_CFB: return "AES-192-CFB";
        case LEGACY_AES_256_CFB: return "AES-256-CFB";
        case LEGACY_AES_128_OFB: return "AES-128-OFB";
        case LEGACY_AES_192_OFB: return "AES-192-OFB";
        case LEGACY_AES_256_OFB: return "AES-256-OFB";
        case LEGACY_AES_128_ECB: return "AES-128-ECB";
        case LEGACY_AES_192_ECB: return "AES-192-ECB";
        case LEGACY_AES_256_ECB: return "AES-256-ECB";
        default: return nullptr;
        }
    }
    // -----------------------------------------------------------------------------

    bool IsPaddedLegacyAlgorithm(const LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case LEGACY_AES_128_CBC:
        case LEGACY_AES_192_CBC:
        case LEGACY_AES_256_CBC:
        case LEGACY_AES_128_ECB:
        case LEGACY_AES_192_ECB:
        case LEGACY_AES_256_ECB:
            return true;
        default:
            return false;
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

    // --- Hash (IHashService) -----------------------------------------------------------------

    // All EVP_XXX() lookups below return process-lifetime static singletons (not owned, never
    // freed) -- this covers every value in HashAlgorithm; OpenSSL 4.0.2's EVP layer has no gaps
    // here (confirmed against the vendored evp.h declarations), unlike Microsoft/CNG and CryptoPP.
    const EVP_MD* HashAlgorithmDigest(const HashAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case HASH_MD5:        return EVP_md5();
        case HASH_SHA1:       return EVP_sha1();
        case HASH_SHA224:     return EVP_sha224();
        case HASH_SHA256:     return EVP_sha256();
        case HASH_SHA384:     return EVP_sha384();
        case HASH_SHA512:     return EVP_sha512();
        case HASH_SHA512_256: return EVP_sha512_256();
        case HASH_SHA3_224:   return EVP_sha3_224();
        case HASH_SHA3_256:   return EVP_sha3_256();
        case HASH_SHA3_384:   return EVP_sha3_384();
        case HASH_SHA3_512:   return EVP_sha3_512();
        case HASH_BLAKE2B:    return EVP_blake2b512();
        case HASH_BLAKE2S:    return EVP_blake2s256();
        case HASH_RIPEMD160:  return EVP_ripemd160();
        default:              return nullptr;
        }
    }
    // -----------------------------------------------------------------------------
}

struct COpenSslProvider::Impl
{
    EVP_CIPHER* cipher;
    EVP_CIPHER_CTX* encryptCtx;
    EVP_CIPHER_CTX* decryptCtx;
    std::vector<unsigned char> key;
    bool legacySelected;
    bool isCcm;
    bool isPadded;
    unsigned int keySize;
    unsigned int ivOrNonceSize;
    unsigned int tagSize;
    unsigned int blockSize;

    unsigned int rsaKeyBits;
    bool rsaKeyGenerated;
    EVP_PKEY* rsaKey;

    // IHashService state. hashAlgorithm is a static EVP_MD* (not owned, EVP_shaXXX()/EVP_md5()
    // etc. return process-lifetime singletons -- no EVP_MD_free needed). hashCtx is the mutable
    // digest state, reset via EVP_DigestInit_ex for each Init().
    const EVP_MD* hashAlgorithm;
    EVP_MD_CTX* hashCtx;

    Impl()
        : cipher(nullptr), encryptCtx(EVP_CIPHER_CTX_new()), decryptCtx(EVP_CIPHER_CTX_new()),
          legacySelected(false), isCcm(false), isPadded(false), keySize(0), ivOrNonceSize(0),
          tagSize(0), blockSize(0), rsaKeyBits(0), rsaKeyGenerated(false), rsaKey(nullptr),
          hashAlgorithm(nullptr), hashCtx(nullptr)
    {
    }
    // -----------------------------------------------------------------------------

    ~Impl()
    {
        EVP_CIPHER_CTX_free(encryptCtx);
        EVP_CIPHER_CTX_free(decryptCtx);
        if (cipher != nullptr)
        {
            EVP_CIPHER_free(cipher);
        }
        if (rsaKey != nullptr)
        {
            EVP_PKEY_free(rsaKey);
        }
        if (hashCtx != nullptr)
        {
            EVP_MD_CTX_free(hashCtx);
        }
    }
    // -----------------------------------------------------------------------------
};

COpenSslProvider::~COpenSslProvider()
{
}
// -----------------------------------------------------------------------------

COpenSslProvider::COpenSslProvider() : impl_(new Impl())
{
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Initialize(void)
{
    try
    {
        return impl_ != nullptr && impl_->encryptCtx != nullptr && impl_->decryptCtx != nullptr;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::SelectAlgorithm(const AeadAlgorithm algorithm)
{
    try
    {
        const char* name = AeadCipherName(algorithm);
        if (name == nullptr)
        {
            return false;
        }

        EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, name, nullptr);
        if (cipher == nullptr)
        {
            return false;
        }

        if (impl_->cipher != nullptr)
        {
            EVP_CIPHER_free(impl_->cipher);
        }
        impl_->cipher = cipher;
        impl_->legacySelected = false;
        impl_->isCcm = IsCcmAlgorithm(algorithm);
        impl_->isPadded = false;
        impl_->keySize = static_cast<unsigned int>(EVP_CIPHER_get_key_length(cipher));
        impl_->ivOrNonceSize = static_cast<unsigned int>(EVP_CIPHER_get_iv_length(cipher));
        impl_->tagSize = OPENSSL_PROVIDER_TAG_SIZE;
        impl_->blockSize = static_cast<unsigned int>(EVP_CIPHER_get_block_size(cipher));
        impl_->key.assign(impl_->keySize, 0);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::SelectAlgorithm(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        const char* name = LegacyCipherName(algorithm);
        if (name == nullptr)
        {
            return false;
        }

        EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, name, nullptr);
        if (cipher == nullptr)
        {
            return false;
        }

        if (impl_->cipher != nullptr)
        {
            EVP_CIPHER_free(impl_->cipher);
        }
        impl_->cipher = cipher;
        impl_->legacySelected = true;
        impl_->isCcm = false;
        impl_->isPadded = IsPaddedLegacyAlgorithm(algorithm);
        impl_->keySize = static_cast<unsigned int>(EVP_CIPHER_get_key_length(cipher));
        impl_->ivOrNonceSize = static_cast<unsigned int>(EVP_CIPHER_get_iv_length(cipher));
        impl_->tagSize = 0;
        impl_->blockSize = static_cast<unsigned int>(EVP_CIPHER_get_block_size(cipher));
        impl_->key.assign(impl_->keySize, 0);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetKeySize(void) const
{
    return impl_->keySize;
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (key == nullptr || keySize != impl_->keySize || impl_->cipher == nullptr)
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

unsigned int COpenSslProvider::GetNonceSize(void) const
{
    return impl_->legacySelected ? 0 : impl_->ivOrNonceSize;
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetTagSize(void) const
{
    return impl_->legacySelected ? 0 : impl_->tagSize;
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (impl_->legacySelected || impl_->cipher == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }
        if (impl_->ivOrNonceSize > 0 && nonce == nullptr)
        {
            return false;
        }

        EVP_CIPHER_CTX* ctx = impl_->encryptCtx;

        if (EVP_EncryptInit_ex2(ctx, impl_->cipher, nullptr, nullptr, nullptr) != 1)
        {
            return false;
        }

        if (impl_->ivOrNonceSize > 0 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonceSize), nullptr) != 1)
        {
            return false;
        }

        if (impl_->isCcm &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tagSize), nullptr) != 1)
        {
            return false;
        }

        if (EVP_EncryptInit_ex2(ctx, nullptr, impl_->key.data(), nonce, nullptr) != 1)
        {
            return false;
        }

        // CCM needs the total plaintext length declared upfront via a NULL-buffer Update call
        // before the real data is processed; GCM/ChaCha20-Poly1305/SIV do not need this.
        if (impl_->isCcm)
        {
            int declaredLength = 0;
            if (EVP_EncryptUpdate(ctx, nullptr, &declaredLength, nullptr, static_cast<int>(inputBufferSize)) != 1)
            {
                return false;
            }
        }

        int updateLength = 0;
        if (inputBufferSize > 0 &&
            EVP_EncryptUpdate(ctx, outputBuffer, &updateLength, inputBuffer, static_cast<int>(inputBufferSize)) != 1)
        {
            return false;
        }

        int finalLength = 0;
        if (EVP_EncryptFinal_ex(ctx, outputBuffer + updateLength, &finalLength) != 1)
        {
            return false;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tagSize), tag) != 1)
        {
            return false;
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Decrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, const unsigned char* tag, const unsigned int tagSize, unsigned char* outputBuffer)
{
    try
    {
        if (impl_->legacySelected || impl_->cipher == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }
        if (impl_->ivOrNonceSize > 0 && nonce == nullptr)
        {
            return false;
        }

        EVP_CIPHER_CTX* ctx = impl_->decryptCtx;

        if (EVP_DecryptInit_ex2(ctx, impl_->cipher, nullptr, nullptr, nullptr) != 1)
        {
            return false;
        }

        if (impl_->ivOrNonceSize > 0 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonceSize), nullptr) != 1)
        {
            return false;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tagSize), const_cast<unsigned char*>(tag)) != 1)
        {
            return false;
        }

        if (EVP_DecryptInit_ex2(ctx, nullptr, impl_->key.data(), nonce, nullptr) != 1)
        {
            return false;
        }

        if (impl_->isCcm)
        {
            int declaredLength = 0;
            if (EVP_DecryptUpdate(ctx, nullptr, &declaredLength, nullptr, static_cast<int>(inputBufferSize)) != 1)
            {
                return false;
            }
        }

        int updateLength = 0;
        if (inputBufferSize > 0 &&
            EVP_DecryptUpdate(ctx, outputBuffer, &updateLength, inputBuffer, static_cast<int>(inputBufferSize)) != 1)
        {
            return false;
        }

        int finalLength = 0;
        return EVP_DecryptFinal_ex(ctx, outputBuffer + updateLength, &finalLength) == 1;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetIvSize(void) const
{
    return impl_->legacySelected ? impl_->ivOrNonceSize : 0;
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetBlockSize(void) const
{
    return impl_->blockSize;
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Encrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->legacySelected || impl_->cipher == nullptr || outputBufferSize == nullptr)
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

        const size_t required = impl_->isPadded
            ? ((static_cast<size_t>(inputBufferSize) / impl_->blockSize) + 1) * impl_->blockSize
            : inputBufferSize;
        if (outputBufferCapacity == 0 || outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = static_cast<unsigned int>(required);
            return false;
        }

        EVP_CIPHER_CTX* ctx = impl_->encryptCtx;
        if (EVP_EncryptInit_ex2(ctx, impl_->cipher, impl_->key.data(), iv, nullptr) != 1)
        {
            return false;
        }
        EVP_CIPHER_CTX_set_padding(ctx, impl_->isPadded ? 1 : 0);

        int updateLength = 0;
        if (inputBufferSize > 0 &&
            EVP_EncryptUpdate(ctx, outputBuffer, &updateLength, inputBuffer, static_cast<int>(inputBufferSize)) != 1)
        {
            return false;
        }

        int finalLength = 0;
        if (EVP_EncryptFinal_ex(ctx, outputBuffer + updateLength, &finalLength) != 1)
        {
            return false;
        }

        *outputBufferSize = static_cast<unsigned int>(updateLength + finalLength);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Decrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->legacySelected || impl_->cipher == nullptr || outputBufferSize == nullptr)
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

        const size_t required = inputBufferSize;
        if (outputBufferCapacity == 0 || outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = static_cast<unsigned int>(required);
            return false;
        }

        EVP_CIPHER_CTX* ctx = impl_->decryptCtx;
        if (EVP_DecryptInit_ex2(ctx, impl_->cipher, impl_->key.data(), iv, nullptr) != 1)
        {
            return false;
        }
        EVP_CIPHER_CTX_set_padding(ctx, impl_->isPadded ? 1 : 0);

        int updateLength = 0;
        if (inputBufferSize > 0 &&
            EVP_DecryptUpdate(ctx, outputBuffer, &updateLength, inputBuffer, static_cast<int>(inputBufferSize)) != 1)
        {
            return false;
        }

        int finalLength = 0;
        if (EVP_DecryptFinal_ex(ctx, outputBuffer + updateLength, &finalLength) != 1)
        {
            return false;
        }

        *outputBufferSize = static_cast<unsigned int>(updateLength + finalLength);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::DerivePasswordKey(const char* password, const unsigned int passwordSize, const unsigned char* salt, const unsigned int saltSize, const unsigned int iterationCount, unsigned char* derivedKey, const unsigned int derivedKeySize)
{
    try
    {
        if (password == nullptr || salt == nullptr || derivedKey == nullptr)
        {
            return false;
        }

        return PKCS5_PBKDF2_HMAC(password, static_cast<int>(passwordSize),
                                  salt, static_cast<int>(saltSize),
                                  static_cast<int>(iterationCount),
                                  EVP_sha256(),
                                  static_cast<int>(derivedKeySize), derivedKey) == 1;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize)
{
    try
    {
        if (buffer == nullptr && bufferSize > 0)
        {
            return false;
        }

        if (bufferSize == 0)
        {
            return true;
        }

        return RAND_bytes(buffer, static_cast<int>(bufferSize)) == 1;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::SelectAlgorithm(const AsymmetricAlgorithm algorithm)
{
    try
    {
        const unsigned int keyBits = AsymmetricKeyBits(algorithm);
        if (keyBits == 0)
        {
            return false;
        }

        impl_->rsaKeyBits = keyBits;
        impl_->rsaKeyGenerated = false;
        if (impl_->rsaKey != nullptr)
        {
            EVP_PKEY_free(impl_->rsaKey);
            impl_->rsaKey = nullptr;
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::GenerateKeyPair(void)
{
    try
    {
        if (impl_->rsaKeyBits == 0)
        {
            return false;
        }

        EVP_PKEY_CTX* genCtx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (genCtx == nullptr)
        {
            return false;
        }

        if (EVP_PKEY_keygen_init(genCtx) != 1 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(genCtx, static_cast<int>(impl_->rsaKeyBits)) != 1)
        {
            EVP_PKEY_CTX_free(genCtx);
            return false;
        }

        EVP_PKEY* newKey = nullptr;
        if (EVP_PKEY_generate(genCtx, &newKey) != 1)
        {
            EVP_PKEY_CTX_free(genCtx);
            return false;
        }

        EVP_PKEY_CTX_free(genCtx);

        if (impl_->rsaKey != nullptr)
        {
            EVP_PKEY_free(impl_->rsaKey);
        }
        impl_->rsaKey = newKey;
        impl_->rsaKeyGenerated = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetMaxPlaintextSize(void) const
{
    try
    {
        if (!impl_->rsaKeyGenerated || impl_->rsaKey == nullptr)
        {
            return 0;
        }

        const int keyBytes = EVP_PKEY_get_size(impl_->rsaKey);
        const int oaepOverhead = 2 * 32 + 2; // SHA-256 OAEP: 2*hashLen + 2
        return keyBytes > oaepOverhead ? static_cast<unsigned int>(keyBytes - oaepOverhead) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetCiphertextSize(void) const
{
    try
    {
        if (!impl_->rsaKeyGenerated || impl_->rsaKey == nullptr)
        {
            return 0;
        }

        return static_cast<unsigned int>(EVP_PKEY_get_size(impl_->rsaKey));
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Encrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->rsaKeyGenerated || impl_->rsaKey == nullptr || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, impl_->rsaKey, nullptr);
        if (ctx == nullptr)
        {
            return false;
        }

        if (EVP_PKEY_encrypt_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) != 1)
        {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        size_t requiredSize = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &requiredSize, inputBuffer, inputBufferSize) != 1)
        {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = static_cast<unsigned int>(requiredSize);
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        size_t actualSize = requiredSize;
        if (EVP_PKEY_encrypt(ctx, outputBuffer, &actualSize, inputBuffer, inputBufferSize) != 1)
        {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        EVP_PKEY_CTX_free(ctx);
        *outputBufferSize = static_cast<unsigned int>(actualSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Decrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->rsaKeyGenerated || impl_->rsaKey == nullptr || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, impl_->rsaKey, nullptr);
        if (ctx == nullptr)
        {
            return false;
        }

        if (EVP_PKEY_decrypt_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) != 1)
        {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        size_t requiredSize = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &requiredSize, inputBuffer, inputBufferSize) != 1)
        {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = static_cast<unsigned int>(requiredSize);
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        size_t actualSize = requiredSize;
        if (EVP_PKEY_decrypt(ctx, outputBuffer, &actualSize, inputBuffer, inputBufferSize) != 1)
        {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        EVP_PKEY_CTX_free(ctx);
        *outputBufferSize = static_cast<unsigned int>(actualSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetMacSize(void) const
{
    return 32; // HMAC-SHA256
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::ComputeMac(const unsigned char* key, const unsigned int keySize, const unsigned char* data, const unsigned int dataSize, unsigned char* mac, const unsigned int macSize)
{
    try
    {
        if (key == nullptr || keySize == 0 || mac == nullptr || macSize != 32 ||
            (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        unsigned int actualSize = 0;
        if (HMAC(EVP_sha256(), key, static_cast<int>(keySize), data, dataSize, mac, &actualSize) == nullptr)
        {
            return false;
        }

        return actualSize == macSize;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::SelectAlgorithm(const HashAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        const EVP_MD* digest = HashAlgorithmDigest(algorithm);
        if (digest == nullptr)
        {
            return false;
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == nullptr)
        {
            return false;
        }

        if (impl_->hashCtx != nullptr)
        {
            EVP_MD_CTX_free(impl_->hashCtx);
        }

        impl_->hashCtx = ctx;
        impl_->hashAlgorithm = digest;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetHashSize(void) const
{
    try
    {
        return (impl_ && impl_->hashAlgorithm) ? static_cast<unsigned int>(EVP_MD_get_size(impl_->hashAlgorithm)) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::ComputeHash(const unsigned char* data, const unsigned int dataSize, unsigned char* hash, const unsigned int hashSize)
{
    return Init() && Update(data, dataSize) && Final(hash, hashSize);
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Init(void)
{
    try
    {
        if (!impl_ || impl_->hashCtx == nullptr || impl_->hashAlgorithm == nullptr)
        {
            return false;
        }

        return EVP_DigestInit_ex(impl_->hashCtx, impl_->hashAlgorithm, nullptr) == 1;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Update(const unsigned char* data, const unsigned int dataSize)
{
    try
    {
        if (!impl_ || impl_->hashCtx == nullptr || (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        if (dataSize == 0)
        {
            return true;
        }

        return EVP_DigestUpdate(impl_->hashCtx, data, dataSize) == 1;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Final(unsigned char* hash, const unsigned int hashSize)
{
    try
    {
        if (!impl_ || impl_->hashCtx == nullptr || impl_->hashAlgorithm == nullptr || hash == nullptr ||
            hashSize < static_cast<unsigned int>(EVP_MD_get_size(impl_->hashAlgorithm)))
        {
            return false;
        }

        unsigned int actualSize = 0;
        return EVP_DigestFinal_ex(impl_->hashCtx, hash, &actualSize) == 1 && actualSize <= hashSize;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

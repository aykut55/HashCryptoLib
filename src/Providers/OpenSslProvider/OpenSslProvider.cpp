#include "OpenSslProvider.h"

#include "openssl/evp.h"
#include "openssl/rand.h"

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

    Impl()
        : cipher(nullptr), encryptCtx(EVP_CIPHER_CTX_new()), decryptCtx(EVP_CIPHER_CTX_new()),
          legacySelected(false), isCcm(false), isPadded(false), keySize(0), ivOrNonceSize(0),
          tagSize(0), blockSize(0)
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

} // namespace CryptoApiNS

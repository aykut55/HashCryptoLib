#include "OpenSslProvider.h"

#include "openssl/evp.h"
#include "openssl/rand.h"

#include <cstring>

namespace CryptoApiNS
{

namespace
{
    const unsigned int OPENSSL_PROVIDER_KEY_SIZE = 32;
    const unsigned int OPENSSL_PROVIDER_NONCE_SIZE = 12;
    const unsigned int OPENSSL_PROVIDER_TAG_SIZE = 16;
}

struct COpenSslProvider::Impl
{
    EVP_CIPHER_CTX* encryptCtx;
    EVP_CIPHER_CTX* decryptCtx;
    unsigned char key[OPENSSL_PROVIDER_KEY_SIZE];

    Impl() : encryptCtx(EVP_CIPHER_CTX_new()), decryptCtx(EVP_CIPHER_CTX_new())
    {
    }
    // -----------------------------------------------------------------------------

    ~Impl()
    {
        EVP_CIPHER_CTX_free(encryptCtx);
        EVP_CIPHER_CTX_free(decryptCtx);
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

unsigned int COpenSslProvider::GetKeySize(void) const
{
    return OPENSSL_PROVIDER_KEY_SIZE;
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetNonceSize(void) const
{
    return OPENSSL_PROVIDER_NONCE_SIZE;
}
// -----------------------------------------------------------------------------

unsigned int COpenSslProvider::GetTagSize(void) const
{
    return OPENSSL_PROVIDER_TAG_SIZE;
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (key == nullptr || keySize != OPENSSL_PROVIDER_KEY_SIZE)
        {
            return false;
        }

        std::memcpy(impl_->key, key, OPENSSL_PROVIDER_KEY_SIZE);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool COpenSslProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        EVP_CIPHER_CTX* ctx = impl_->encryptCtx;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        {
            return false;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonceSize), nullptr) != 1)
        {
            return false;
        }

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, impl_->key, nonce) != 1)
        {
            return false;
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

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tagSize), tag) != 1)
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
        if (nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        EVP_CIPHER_CTX* ctx = impl_->decryptCtx;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        {
            return false;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonceSize), nullptr) != 1)
        {
            return false;
        }

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, impl_->key, nonce) != 1)
        {
            return false;
        }

        int updateLength = 0;
        if (inputBufferSize > 0 &&
            EVP_DecryptUpdate(ctx, outputBuffer, &updateLength, inputBuffer, static_cast<int>(inputBufferSize)) != 1)
        {
            return false;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tagSize), const_cast<unsigned char*>(tag)) != 1)
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

#include "CryptoPPModernProvider.h"

#include "cryptopp/aes.h"
#include "cryptopp/gcm.h"
#include "cryptopp/osrng.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"

namespace CryptoApiNS
{

namespace
{
    const unsigned int CRYPTOPP_MODERN_PROVIDER_KEY_SIZE = 32;
    const unsigned int CRYPTOPP_MODERN_PROVIDER_NONCE_SIZE = 12;
    const unsigned int CRYPTOPP_MODERN_PROVIDER_TAG_SIZE = 16;
}

struct CCryptoPPModernProvider::Impl
{
    CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
    CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
};

CCryptoPPModernProvider::~CCryptoPPModernProvider()
{
}
// -----------------------------------------------------------------------------

CCryptoPPModernProvider::CCryptoPPModernProvider() : impl_(new Impl())
{
}
// -----------------------------------------------------------------------------

bool CCryptoPPModernProvider::Initialize(void)
{
    try
    {
        return impl_ != nullptr;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPModernProvider::GetKeySize(void) const
{
    return CRYPTOPP_MODERN_PROVIDER_KEY_SIZE;
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPModernProvider::GetNonceSize(void) const
{
    return CRYPTOPP_MODERN_PROVIDER_NONCE_SIZE;
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPModernProvider::GetTagSize(void) const
{
    return CRYPTOPP_MODERN_PROVIDER_TAG_SIZE;
}
// -----------------------------------------------------------------------------

bool CCryptoPPModernProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (key == nullptr || keySize != CRYPTOPP_MODERN_PROVIDER_KEY_SIZE)
        {
            return false;
        }

        const CryptoPP::byte* keyBytes = reinterpret_cast<const CryptoPP::byte*>(key);

        // GCM is a resynchronizable mode, so SetKey requires an IV to be present even though the
        // real per-message nonce is applied later by Encrypt/Decrypt via EncryptAndAuthenticate/
        // DecryptAndVerify, which call Resynchronize(iv, ...) themselves. This placeholder IV is
        // therefore never actually used for any ciphertext.
        CryptoPP::byte placeholderIv[CRYPTOPP_MODERN_PROVIDER_NONCE_SIZE] = {};
        impl_->encryption.SetKeyWithIV(keyBytes, keySize, placeholderIv, sizeof(placeholderIv));
        impl_->decryption.SetKeyWithIV(keyBytes, keySize, placeholderIv, sizeof(placeholderIv));
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPModernProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        impl_->encryption.EncryptAndAuthenticate(reinterpret_cast<CryptoPP::byte*>(outputBuffer),
                                                 reinterpret_cast<CryptoPP::byte*>(tag), tagSize,
                                                 reinterpret_cast<const CryptoPP::byte*>(nonce), static_cast<int>(nonceSize),
                                                 nullptr, 0,
                                                 reinterpret_cast<const CryptoPP::byte*>(inputBuffer), inputBufferSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPModernProvider::Decrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, const unsigned char* tag, const unsigned int tagSize, unsigned char* outputBuffer)
{
    try
    {
        if (nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        return impl_->decryption.DecryptAndVerify(reinterpret_cast<CryptoPP::byte*>(outputBuffer),
                                                   reinterpret_cast<const CryptoPP::byte*>(tag), tagSize,
                                                   reinterpret_cast<const CryptoPP::byte*>(nonce), static_cast<int>(nonceSize),
                                                   nullptr, 0,
                                                   reinterpret_cast<const CryptoPP::byte*>(inputBuffer), inputBufferSize);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPModernProvider::DerivePasswordKey(const char* password, const unsigned int passwordSize, const unsigned char* salt, const unsigned int saltSize, const unsigned int iterationCount, unsigned char* derivedKey, const unsigned int derivedKeySize)
{
    try
    {
        if (password == nullptr || salt == nullptr || derivedKey == nullptr)
        {
            return false;
        }

        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
        pbkdf2.DeriveKey(reinterpret_cast<CryptoPP::byte*>(derivedKey), derivedKeySize,
                         0,
                         reinterpret_cast<const CryptoPP::byte*>(password), passwordSize,
                         reinterpret_cast<const CryptoPP::byte*>(salt), saltSize,
                         iterationCount);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPModernProvider::GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize)
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

        CryptoPP::OS_GenerateRandomBlock(true, reinterpret_cast<CryptoPP::byte*>(buffer), bufferSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

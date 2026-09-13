#include "BotanProvider.h"

#include "botan_all.h"

#include <cstring>

namespace CryptoApiNS
{

namespace
{
    const unsigned int BOTAN_PROVIDER_KEY_SIZE = 32;
    const unsigned int BOTAN_PROVIDER_NONCE_SIZE = 12;
    const unsigned int BOTAN_PROVIDER_TAG_SIZE = 16;
}

struct CBotanProvider::Impl
{
    std::unique_ptr<Botan::AEAD_Mode> encryption;
    std::unique_ptr<Botan::AEAD_Mode> decryption;
};

CBotanProvider::~CBotanProvider()
{
}
// -----------------------------------------------------------------------------

CBotanProvider::CBotanProvider() : impl_(new Impl())
{
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Initialize(void)
{
    try
    {
        impl_->encryption = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        impl_->decryption = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        return impl_->encryption != nullptr && impl_->decryption != nullptr;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetKeySize(void) const
{
    return BOTAN_PROVIDER_KEY_SIZE;
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetNonceSize(void) const
{
    return BOTAN_PROVIDER_NONCE_SIZE;
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetTagSize(void) const
{
    return BOTAN_PROVIDER_TAG_SIZE;
}
// -----------------------------------------------------------------------------

bool CBotanProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (key == nullptr || keySize != BOTAN_PROVIDER_KEY_SIZE ||
            !impl_->encryption || !impl_->decryption)
        {
            return false;
        }

        impl_->encryption->set_key(key, keySize);
        impl_->decryption->set_key(key, keySize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        Botan::secure_vector<uint8_t> buffer(inputBuffer, inputBuffer + inputBufferSize);
        impl_->encryption->start(nonce, nonceSize);
        impl_->encryption->finish(buffer);

        if (buffer.size() != static_cast<std::size_t>(inputBufferSize) + tagSize)
        {
            return false;
        }

        if (inputBufferSize > 0)
        {
            std::memcpy(outputBuffer, buffer.data(), inputBufferSize);
        }

        std::memcpy(tag, buffer.data() + inputBufferSize, tagSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Decrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, const unsigned char* tag, const unsigned int tagSize, unsigned char* outputBuffer)
{
    try
    {
        if (nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        Botan::secure_vector<uint8_t> buffer;
        buffer.reserve(static_cast<std::size_t>(inputBufferSize) + tagSize);
        buffer.insert(buffer.end(), inputBuffer, inputBuffer + inputBufferSize);
        buffer.insert(buffer.end(), tag, tag + tagSize);

        impl_->decryption->start(nonce, nonceSize);
        impl_->decryption->finish(buffer);

        if (buffer.size() != inputBufferSize)
        {
            return false;
        }

        if (inputBufferSize > 0)
        {
            std::memcpy(outputBuffer, buffer.data(), inputBufferSize);
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::DerivePasswordKey(const char* password, const unsigned int passwordSize, const unsigned char* salt, const unsigned int saltSize, const unsigned int iterationCount, unsigned char* derivedKey, const unsigned int derivedKeySize)
{
    try
    {
        if (password == nullptr || salt == nullptr || derivedKey == nullptr)
        {
            return false;
        }

        std::unique_ptr<Botan::MessageAuthenticationCode> hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        if (!hmac)
        {
            return false;
        }

        Botan::PBKDF2 pbkdf2(*hmac, iterationCount);
        pbkdf2.derive_key(derivedKey, derivedKeySize, password, passwordSize, salt, saltSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize)
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

        Botan::System_RNG rng;
        rng.randomize(buffer, bufferSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

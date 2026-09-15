#include "BotanProvider.h"

#include "botan_all.h"

#include <cstring>

namespace CryptoApiNS
{

namespace
{
    const char* AeadAlgorithmName(const AeadAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case AEAD_AES_128_GCM: return "AES-128/GCM";
        case AEAD_AES_192_GCM: return "AES-192/GCM";
        case AEAD_AES_256_GCM: return "AES-256/GCM";
        case AEAD_AES_128_CCM: return "AES-128/CCM";
        case AEAD_AES_192_CCM: return "AES-192/CCM";
        case AEAD_AES_256_CCM: return "AES-256/CCM";
        case AEAD_AES_128_EAX: return "AES-128/EAX";
        case AEAD_AES_192_EAX: return "AES-192/EAX";
        case AEAD_AES_256_EAX: return "AES-256/EAX";
        case AEAD_AES_128_SIV: return "AES-128/SIV";
        case AEAD_AES_256_SIV: return "AES-256/SIV";
        case AEAD_AES_128_GCM_SIV: return "AES-128/GCM-SIV";
        case AEAD_AES_256_GCM_SIV: return "AES-256/GCM-SIV";
        case AEAD_CHACHA20_POLY1305: return "ChaCha20Poly1305";
        case AEAD_TWOFISH_GCM: return "Twofish/GCM";
        case AEAD_SERPENT_GCM: return "Serpent/GCM";
        case AEAD_CAMELLIA_GCM: return "Camellia-256/GCM";
        default: return nullptr;
        }
    }
    // -----------------------------------------------------------------------------

    const char* LegacyAlgorithmName(const LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case LEGACY_AES_128_CBC: return "AES-128/CBC/PKCS7";
        case LEGACY_AES_192_CBC: return "AES-192/CBC/PKCS7";
        case LEGACY_AES_256_CBC: return "AES-256/CBC/PKCS7";
        case LEGACY_AES_128_CTR: return "AES-128/CTR-BE";
        case LEGACY_AES_192_CTR: return "AES-192/CTR-BE";
        case LEGACY_AES_256_CTR: return "AES-256/CTR-BE";
        case LEGACY_AES_128_CFB: return "AES-128/CFB";
        case LEGACY_AES_192_CFB: return "AES-192/CFB";
        case LEGACY_AES_256_CFB: return "AES-256/CFB";
        case LEGACY_AES_128_OFB: return "AES-128/OFB";
        case LEGACY_AES_192_OFB: return "AES-192/OFB";
        case LEGACY_AES_256_OFB: return "AES-256/OFB";
        case LEGACY_AES_128_ECB:
        case LEGACY_AES_192_ECB:
        case LEGACY_AES_256_ECB:
        default:
            // Botan 3.x deliberately has no standalone ECB Cipher_Mode factory entry.
            return nullptr;
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

    // BLAKE2b(512)/BLAKE2s(256) are Botan's algorithm-name strings for the conventional full-size
    // default (see HashAlgorithm's doc comment in ProviderTypes.h). No Botan class exists for
    // truncated SHA-3-224; SHA-512-256 does exist (sha2_64 module) as "SHA-512-256".
    const char* HashAlgorithmName(const HashAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case HASH_MD5:        return "MD5";
        case HASH_SHA1:       return "SHA-1";
        case HASH_SHA224:     return "SHA-224";
        case HASH_SHA256:     return "SHA-256";
        case HASH_SHA384:     return "SHA-384";
        case HASH_SHA512:     return "SHA-512";
        case HASH_SHA512_256: return "SHA-512-256";
        case HASH_SHA3_224:   return "SHA-3(224)";
        case HASH_SHA3_256:   return "SHA-3(256)";
        case HASH_SHA3_384:   return "SHA-3(384)";
        case HASH_SHA3_512:   return "SHA-3(512)";
        case HASH_BLAKE2B:    return "BLAKE2b(512)";
        case HASH_BLAKE2S:    return "BLAKE2s(256)";
        case HASH_RIPEMD160:  return "RIPEMD-160";
        default:              return nullptr;
        }
    }
    // -----------------------------------------------------------------------------
}

struct CBotanProvider::Impl
{
    std::unique_ptr<Botan::AEAD_Mode> aeadEncryption;
    std::unique_ptr<Botan::AEAD_Mode> aeadDecryption;
    std::unique_ptr<Botan::Cipher_Mode> legacyEncryption;
    std::unique_ptr<Botan::Cipher_Mode> legacyDecryption;
    bool legacySelected = false;

    unsigned int rsaKeyBits = 0;
    bool rsaKeyGenerated = false;
    std::unique_ptr<Botan::RSA_PrivateKey> rsaPrivateKey;

    // IHashService state.
    std::unique_ptr<Botan::HashFunction> hashFunction;
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
        return impl_ != nullptr;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::SelectAlgorithm(const AeadAlgorithm algorithm)
{
    try
    {
        const char* name = AeadAlgorithmName(algorithm);
        if (name == nullptr)
        {
            return false;
        }

        std::unique_ptr<Botan::AEAD_Mode> encryption = Botan::AEAD_Mode::create(name, Botan::Cipher_Dir::Encryption);
        std::unique_ptr<Botan::AEAD_Mode> decryption = Botan::AEAD_Mode::create(name, Botan::Cipher_Dir::Decryption);
        if (!encryption || !decryption)
        {
            return false;
        }

        impl_->aeadEncryption = std::move(encryption);
        impl_->aeadDecryption = std::move(decryption);
        impl_->legacyEncryption.reset();
        impl_->legacyDecryption.reset();
        impl_->legacySelected = false;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::SelectAlgorithm(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        const char* name = LegacyAlgorithmName(algorithm);
        if (name == nullptr)
        {
            return false;
        }

        std::unique_ptr<Botan::Cipher_Mode> encryption = Botan::Cipher_Mode::create(name, Botan::Cipher_Dir::Encryption);
        std::unique_ptr<Botan::Cipher_Mode> decryption = Botan::Cipher_Mode::create(name, Botan::Cipher_Dir::Decryption);
        if (!encryption || !decryption)
        {
            return false;
        }

        impl_->legacyEncryption = std::move(encryption);
        impl_->legacyDecryption = std::move(decryption);
        impl_->aeadEncryption.reset();
        impl_->aeadDecryption.reset();
        impl_->legacySelected = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetKeySize(void) const
{
    try
    {
        if (impl_->legacySelected)
        {
            return impl_->legacyEncryption ? static_cast<unsigned int>(impl_->legacyEncryption->minimum_keylength()) : 0;
        }
        return impl_->aeadEncryption ? static_cast<unsigned int>(impl_->aeadEncryption->minimum_keylength()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (key == nullptr)
        {
            return false;
        }

        if (impl_->legacySelected)
        {
            if (!impl_->legacyEncryption || !impl_->legacyDecryption || !impl_->legacyEncryption->valid_keylength(keySize))
            {
                return false;
            }
            impl_->legacyEncryption->set_key(key, keySize);
            impl_->legacyDecryption->set_key(key, keySize);
        }
        else
        {
            if (!impl_->aeadEncryption || !impl_->aeadDecryption || !impl_->aeadEncryption->valid_keylength(keySize))
            {
                return false;
            }
            impl_->aeadEncryption->set_key(key, keySize);
            impl_->aeadDecryption->set_key(key, keySize);
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetNonceSize(void) const
{
    try
    {
        return impl_->aeadEncryption ? static_cast<unsigned int>(impl_->aeadEncryption->default_nonce_length()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetTagSize(void) const
{
    try
    {
        return impl_->aeadEncryption ? static_cast<unsigned int>(impl_->aeadEncryption->tag_size()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (!impl_->aeadEncryption || nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        Botan::secure_vector<uint8_t> buffer(inputBuffer, inputBuffer + inputBufferSize);
        impl_->aeadEncryption->start(nonce, nonceSize);
        impl_->aeadEncryption->finish(buffer);

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
        if (!impl_->aeadDecryption || nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        Botan::secure_vector<uint8_t> buffer;
        buffer.reserve(static_cast<std::size_t>(inputBufferSize) + tagSize);
        buffer.insert(buffer.end(), inputBuffer, inputBuffer + inputBufferSize);
        buffer.insert(buffer.end(), tag, tag + tagSize);

        impl_->aeadDecryption->start(nonce, nonceSize);
        impl_->aeadDecryption->finish(buffer);

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

unsigned int CBotanProvider::GetIvSize(void) const
{
    try
    {
        return impl_->legacyEncryption ? static_cast<unsigned int>(impl_->legacyEncryption->default_nonce_length()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetBlockSize(void) const
{
    // Informational only: Encrypt/Decrypt below size buffers via Botan's own output_length(),
    // not manual block-size arithmetic. All supported legacy algorithms here are AES-based.
    return 16;
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Encrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->legacyEncryption || outputBufferSize == nullptr)
        {
            return false;
        }
        if (iv == nullptr && ivSize > 0)
        {
            return false;
        }
        if (inputBufferSize > 0 && inputBuffer == nullptr)
        {
            return false;
        }

        const size_t required = impl_->legacyEncryption->output_length(inputBufferSize);
        if (outputBufferCapacity == 0 || outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = static_cast<unsigned int>(required);
            return false;
        }

        Botan::secure_vector<uint8_t> buffer(inputBuffer, inputBuffer + inputBufferSize);
        impl_->legacyEncryption->start(iv, ivSize);
        impl_->legacyEncryption->finish(buffer);

        if (buffer.size() > outputBufferCapacity)
        {
            *outputBufferSize = static_cast<unsigned int>(buffer.size());
            return false;
        }

        if (!buffer.empty())
        {
            std::memcpy(outputBuffer, buffer.data(), buffer.size());
        }
        *outputBufferSize = static_cast<unsigned int>(buffer.size());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Decrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->legacyDecryption || outputBufferSize == nullptr)
        {
            return false;
        }
        if (iv == nullptr && ivSize > 0)
        {
            return false;
        }
        if (inputBufferSize > 0 && inputBuffer == nullptr)
        {
            return false;
        }

        const size_t required = impl_->legacyDecryption->output_length(inputBufferSize);
        if (outputBufferCapacity == 0 || outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = static_cast<unsigned int>(required);
            return false;
        }

        Botan::secure_vector<uint8_t> buffer(inputBuffer, inputBuffer + inputBufferSize);
        impl_->legacyDecryption->start(iv, ivSize);
        impl_->legacyDecryption->finish(buffer);

        if (buffer.size() > outputBufferCapacity)
        {
            *outputBufferSize = static_cast<unsigned int>(buffer.size());
            return false;
        }

        if (!buffer.empty())
        {
            std::memcpy(outputBuffer, buffer.data(), buffer.size());
        }
        *outputBufferSize = static_cast<unsigned int>(buffer.size());
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

bool CBotanProvider::SelectAlgorithm(const AsymmetricAlgorithm algorithm)
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
        impl_->rsaPrivateKey.reset();
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::GenerateKeyPair(void)
{
    try
    {
        if (impl_->rsaKeyBits == 0)
        {
            return false;
        }

        Botan::AutoSeeded_RNG rng;
        impl_->rsaPrivateKey.reset(new Botan::RSA_PrivateKey(rng, impl_->rsaKeyBits));
        impl_->rsaKeyGenerated = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetMaxPlaintextSize(void) const
{
    try
    {
        if (!impl_->rsaKeyGenerated || !impl_->rsaPrivateKey)
        {
            return 0;
        }

        Botan::AutoSeeded_RNG rng;
        Botan::PK_Encryptor_EME encryptor(*impl_->rsaPrivateKey, rng, "OAEP(SHA-256)");
        return static_cast<unsigned int>(encryptor.maximum_input_size());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetCiphertextSize(void) const
{
    try
    {
        if (!impl_->rsaKeyGenerated || !impl_->rsaPrivateKey)
        {
            return 0;
        }

        return impl_->rsaKeyBits / 8;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Encrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->rsaKeyGenerated || !impl_->rsaPrivateKey || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        Botan::AutoSeeded_RNG rng;
        Botan::PK_Encryptor_EME encryptor(*impl_->rsaPrivateKey, rng, "OAEP(SHA-256)");
        const size_t requiredSize = encryptor.ciphertext_length(inputBufferSize);
        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = static_cast<unsigned int>(requiredSize);
            return false;
        }

        const std::vector<uint8_t> ciphertext = encryptor.encrypt(inputBuffer, inputBufferSize, rng);
        if (ciphertext.size() > outputBufferCapacity)
        {
            *outputBufferSize = static_cast<unsigned int>(ciphertext.size());
            return false;
        }

        if (!ciphertext.empty())
        {
            std::memcpy(outputBuffer, ciphertext.data(), ciphertext.size());
        }
        *outputBufferSize = static_cast<unsigned int>(ciphertext.size());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Decrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->rsaKeyGenerated || !impl_->rsaPrivateKey || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        Botan::AutoSeeded_RNG rng;
        Botan::PK_Decryptor_EME decryptor(*impl_->rsaPrivateKey, rng, "OAEP(SHA-256)");
        const Botan::secure_vector<uint8_t> plaintext = decryptor.decrypt(inputBuffer, inputBufferSize);

        if (outputBuffer == nullptr || outputBufferCapacity < plaintext.size())
        {
            *outputBufferSize = static_cast<unsigned int>(plaintext.size());
            return false;
        }

        if (!plaintext.empty())
        {
            std::memcpy(outputBuffer, plaintext.data(), plaintext.size());
        }
        *outputBufferSize = static_cast<unsigned int>(plaintext.size());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetMacSize(void) const
{
    return 32; // HMAC-SHA256
}
// -----------------------------------------------------------------------------

bool CBotanProvider::ComputeMac(const unsigned char* key, const unsigned int keySize, const unsigned char* data, const unsigned int dataSize, unsigned char* mac, const unsigned int macSize)
{
    try
    {
        if (key == nullptr || keySize == 0 || mac == nullptr || macSize != 32 ||
            (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        std::unique_ptr<Botan::MessageAuthenticationCode> hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        if (!hmac)
        {
            return false;
        }

        hmac->set_key(key, keySize);
        hmac->update(data, dataSize);
        const Botan::secure_vector<uint8_t> result = hmac->final();
        if (result.size() != macSize)
        {
            return false;
        }

        std::memcpy(mac, result.data(), macSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::SelectAlgorithm(const HashAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        const char* name = HashAlgorithmName(algorithm);
        if (name == nullptr)
        {
            return false;
        }

        std::unique_ptr<Botan::HashFunction> hashFunction = Botan::HashFunction::create(name);
        if (!hashFunction)
        {
            return false;
        }

        impl_->hashFunction = std::move(hashFunction);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBotanProvider::GetHashSize(void) const
{
    try
    {
        return (impl_ && impl_->hashFunction) ? static_cast<unsigned int>(impl_->hashFunction->output_length()) : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::ComputeHash(const unsigned char* data, const unsigned int dataSize, unsigned char* hash, const unsigned int hashSize)
{
    return Init() && Update(data, dataSize) && Final(hash, hashSize);
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Init(void)
{
    try
    {
        if (!impl_ || !impl_->hashFunction)
        {
            return false;
        }

        impl_->hashFunction->clear();
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Update(const unsigned char* data, const unsigned int dataSize)
{
    try
    {
        if (!impl_ || !impl_->hashFunction || (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        if (dataSize > 0)
        {
            impl_->hashFunction->update(data, dataSize);
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CBotanProvider::Final(unsigned char* hash, const unsigned int hashSize)
{
    try
    {
        if (!impl_ || !impl_->hashFunction || hash == nullptr ||
            hashSize < impl_->hashFunction->output_length())
        {
            return false;
        }

        const Botan::secure_vector<uint8_t> result = impl_->hashFunction->final();
        std::memcpy(hash, result.data(), result.size());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

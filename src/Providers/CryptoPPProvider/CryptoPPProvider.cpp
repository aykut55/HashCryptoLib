#include "CryptoPPProvider.h"

#include "cryptopp890/aes.h"
#include "cryptopp890/blake2.h"
#include "cryptopp890/camellia.h"
#include "cryptopp890/ccm.h"
#include "cryptopp890/chachapoly.h"
#include "cryptopp890/eax.h"
#include "cryptopp890/eccrypto.h"
#include "cryptopp890/filters.h"
#include "cryptopp890/gcm.h"
#include "cryptopp890/hmac.h"
#include "cryptopp890/md5.h"
#include "cryptopp890/modes.h"
#include "cryptopp890/oaep.h"
#include "cryptopp890/oids.h"
#include "cryptopp890/osrng.h"
#include "cryptopp890/pssr.h"
#include "cryptopp890/pwdbased.h"
#include "cryptopp890/ripemd.h"
#include "cryptopp890/rsa.h"
#include "cryptopp890/secblock.h"
#include "cryptopp890/serpent.h"
#include "cryptopp890/sha.h"
#include "cryptopp890/sha3.h"
#include "cryptopp890/twofish.h"
#include "cryptopp890/xed25519.h"

#include <memory>

namespace CryptoApiNS
{

namespace
{
    const unsigned int CRYPTOPP_PROVIDER_NONCE_SIZE = 12;
    const unsigned int CRYPTOPP_PROVIDER_TAG_SIZE = 16;
    const unsigned int CRYPTOPP_PROVIDER_BLOCK_SIZE = 16;

    // --- Signature (ISignatureEngine) -----------------------------------------------------------

    // 0 for non-RSA algorithms (ECDSA-P256, Ed25519), which have a fixed key size instead.
    unsigned int SignatureRsaKeyBits(SignatureAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case SIGNATURE_RSA_PSS_SHA256_2048: return 2048;
            case SIGNATURE_RSA_PSS_SHA256_3072: return 3072;
            case SIGNATURE_RSA_PSS_SHA256_4096: return 4096;
            default:                            return 0;
        }
    }

    // --- AEAD engines --------------------------------------------------------------------------

    class IAeadEngine
    {
    public:
        virtual ~IAeadEngine() {}

        virtual void SetKey(const CryptoPP::byte* key, size_t keySize) = 0;

        virtual void Encrypt( CryptoPP::byte* output, CryptoPP::byte* tag, size_t tagSize,
                              const CryptoPP::byte* nonce, int nonceSize,
                              const CryptoPP::byte* input, size_t inputSize) = 0;

        virtual bool Decrypt( CryptoPP::byte* output, const CryptoPP::byte* tag, size_t tagSize,
                             const CryptoPP::byte* nonce, int nonceSize,
                             const CryptoPP::byte* input, size_t inputSize) = 0;
    };

    template <typename SchemeT>
    class AeadEngine : public IAeadEngine
    {
    public:
        void SetKey(const CryptoPP::byte* key, size_t keySize) override
        {
            // GCM/CCM/EAX/ChaCha20Poly1305 are all "resynchronizable": SetKey requires a
            // placeholder IV even though the real per-message nonce is supplied later via
            // EncryptAndAuthenticate/DecryptAndVerify's internal Resynchronize() call.
            CryptoPP::byte placeholderIv[CRYPTOPP_PROVIDER_NONCE_SIZE] = {};
            encryption_.SetKeyWithIV(key, keySize, placeholderIv, sizeof(placeholderIv));
            decryption_.SetKeyWithIV(key, keySize, placeholderIv, sizeof(placeholderIv));
        }
        // -----------------------------------------------------------------------------

        void Encrypt(CryptoPP::byte* output, CryptoPP::byte* tag, size_t tagSize, const CryptoPP::byte* nonce, int nonceSize, const CryptoPP::byte* input, size_t inputSize) override
        {
            encryption_.EncryptAndAuthenticate(output, tag, tagSize, nonce, nonceSize, nullptr, 0, input, inputSize);
        }
        // -----------------------------------------------------------------------------

        bool Decrypt(CryptoPP::byte* output, const CryptoPP::byte* tag, size_t tagSize, const CryptoPP::byte* nonce, int nonceSize, const CryptoPP::byte* input, size_t inputSize) override
        {
            return decryption_.DecryptAndVerify(output, tag, tagSize, nonce, nonceSize, nullptr, 0, input, inputSize);
        }
        // -----------------------------------------------------------------------------

    private:
        typename SchemeT::Encryption encryption_;
        typename SchemeT::Decryption decryption_;
    };

    std::unique_ptr<IAeadEngine> CreateAeadEngine(const AeadAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case AEAD_AES_128_GCM:
        case AEAD_AES_192_GCM:
        case AEAD_AES_256_GCM:
            return std::unique_ptr<IAeadEngine>(new AeadEngine<CryptoPP::GCM<CryptoPP::AES> >());
        case AEAD_AES_128_CCM:
        case AEAD_AES_192_CCM:
        case AEAD_AES_256_CCM:
            return std::unique_ptr<IAeadEngine>(new AeadEngine<CryptoPP::CCM<CryptoPP::AES> >());
        case AEAD_AES_128_EAX:
        case AEAD_AES_192_EAX:
        case AEAD_AES_256_EAX:
            return std::unique_ptr<IAeadEngine>(new AeadEngine<CryptoPP::EAX<CryptoPP::AES> >());
        case AEAD_CHACHA20_POLY1305:
            return std::unique_ptr<IAeadEngine>(new AeadEngine<CryptoPP::ChaCha20Poly1305>());
        case AEAD_TWOFISH_GCM:
            return std::unique_ptr<IAeadEngine>(new AeadEngine<CryptoPP::GCM<CryptoPP::Twofish> >());
        case AEAD_SERPENT_GCM:
            return std::unique_ptr<IAeadEngine>(new AeadEngine<CryptoPP::GCM<CryptoPP::Serpent> >());
        case AEAD_CAMELLIA_GCM:
            return std::unique_ptr<IAeadEngine>(new AeadEngine<CryptoPP::GCM<CryptoPP::Camellia> >());
        case AEAD_AES_128_SIV:
        case AEAD_AES_256_SIV:
        case AEAD_AES_128_GCM_SIV:
        case AEAD_AES_256_GCM_SIV:
        default:
            return nullptr; // CryptoPP 8.9.0 has no built-in SIV / AES-GCM-SIV mode.
        }
    }
    // -----------------------------------------------------------------------------

    unsigned int AeadKeySize(const AeadAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case AEAD_AES_128_GCM:
        case AEAD_AES_128_CCM:
        case AEAD_AES_128_EAX:
        case AEAD_AES_128_SIV:
        case AEAD_AES_128_GCM_SIV:
            return 16;
        case AEAD_AES_192_GCM:
        case AEAD_AES_192_CCM:
        case AEAD_AES_192_EAX:
            return 24;
        case AEAD_AES_256_GCM:
        case AEAD_AES_256_CCM:
        case AEAD_AES_256_EAX:
        case AEAD_AES_256_SIV:
        case AEAD_AES_256_GCM_SIV:
        case AEAD_CHACHA20_POLY1305:
        case AEAD_TWOFISH_GCM:
        case AEAD_SERPENT_GCM:
        case AEAD_CAMELLIA_GCM:
            return 32;
        default:
            return 0;
        }
    }
    // -----------------------------------------------------------------------------

    // --- Legacy (non-authenticated) engines -----------------------------------------------------

    class ILegacyEngine
    {
    public:
        virtual ~ILegacyEngine() {}

        virtual void SetKey(const CryptoPP::byte* key, size_t keySize) = 0;
        virtual size_t RequiredOutputSize(bool encrypting, size_t inputSize) const = 0;

        virtual bool Encrypt( const CryptoPP::byte* iv, const CryptoPP::byte* input, size_t inputSize,
                             CryptoPP::byte* output, size_t outputCapacity, size_t* outputSize) = 0;

        virtual bool Decrypt( const CryptoPP::byte* iv, const CryptoPP::byte* input, size_t inputSize,
                             CryptoPP::byte* output, size_t outputCapacity, size_t* outputSize) = 0;
    };

    // CBC / ECB: block-oriented, PKCS7-padded via StreamTransformationFilter. HasIv is false only
    // for ECB, which has no IV concept at all (IVRequirement() == NOT_RESYNCHRONIZABLE).
    template <typename ModeT, bool HasIv>
    class PaddedBlockEngine : public ILegacyEngine
    {
    public:
        void SetKey(const CryptoPP::byte* key, size_t keySize) override
        {
            key_.Assign(key, keySize);
        }
        // -----------------------------------------------------------------------------

        size_t RequiredOutputSize(bool encrypting, size_t inputSize) const override
        {
            if (encrypting)
            {
                return ((inputSize / CRYPTOPP_PROVIDER_BLOCK_SIZE) + 1) * CRYPTOPP_PROVIDER_BLOCK_SIZE;
            }
            return inputSize;
        }
        // -----------------------------------------------------------------------------

        bool Encrypt(const CryptoPP::byte* iv, const CryptoPP::byte* input, size_t inputSize, CryptoPP::byte* output, size_t outputCapacity, size_t* outputSize) override
        {
            typename ModeT::Encryption cipher;
            if constexpr (HasIv)
            {
                cipher.SetKeyWithIV(key_.data(), key_.size(), iv);
            }
            else
            {
                cipher.SetKey(key_.data(), key_.size());
            }
            CryptoPP::ArraySink sink(output, outputCapacity);
            CryptoPP::ArraySource(input, inputSize, true, new CryptoPP::StreamTransformationFilter(cipher, new CryptoPP::Redirector(sink)));
            *outputSize = static_cast<size_t>(sink.TotalPutLength());
            return true;
        }
        // -----------------------------------------------------------------------------

        bool Decrypt(const CryptoPP::byte* iv, const CryptoPP::byte* input, size_t inputSize, CryptoPP::byte* output, size_t outputCapacity, size_t* outputSize) override
        {
            typename ModeT::Decryption cipher;
            if constexpr (HasIv)
            {
                cipher.SetKeyWithIV(key_.data(), key_.size(), iv);
            }
            else
            {
                cipher.SetKey(key_.data(), key_.size());
            }
            CryptoPP::ArraySink sink(output, outputCapacity);
            try
            {
                CryptoPP::ArraySource(input, inputSize, true, new CryptoPP::StreamTransformationFilter(cipher, new CryptoPP::Redirector(sink)));
            }
            catch (const CryptoPP::Exception&)
            {
                return false;
            }
            *outputSize = static_cast<size_t>(sink.TotalPutLength());
            return true;
        }
        // -----------------------------------------------------------------------------

    private:
        CryptoPP::SecByteBlock key_;
    };

    // CTR / CFB / OFB: stream-like, no padding; ciphertext length always equals plaintext length.
    template <typename ModeT>
    class StreamLikeEngine : public ILegacyEngine
    {
    public:
        void SetKey(const CryptoPP::byte* key, size_t keySize) override
        {
            key_.Assign(key, keySize);
        }
        // -----------------------------------------------------------------------------

        size_t RequiredOutputSize(bool /*encrypting*/, size_t inputSize) const override
        {
            return inputSize;
        }
        // -----------------------------------------------------------------------------

        bool Encrypt(const CryptoPP::byte* iv, const CryptoPP::byte* input, size_t inputSize, CryptoPP::byte* output, size_t outputCapacity, size_t* outputSize) override
        {
            if (outputCapacity < inputSize)
            {
                *outputSize = inputSize;
                return false;
            }
            typename ModeT::Encryption cipher;
            cipher.SetKeyWithIV(key_.data(), key_.size(), iv);
            cipher.ProcessData(output, input, inputSize);
            *outputSize = inputSize;
            return true;
        }
        // -----------------------------------------------------------------------------

        bool Decrypt(const CryptoPP::byte* iv, const CryptoPP::byte* input, size_t inputSize, CryptoPP::byte* output, size_t outputCapacity, size_t* outputSize) override
        {
            if (outputCapacity < inputSize)
            {
                *outputSize = inputSize;
                return false;
            }
            typename ModeT::Decryption cipher;
            cipher.SetKeyWithIV(key_.data(), key_.size(), iv);
            cipher.ProcessData(output, input, inputSize);
            *outputSize = inputSize;
            return true;
        }
        // -----------------------------------------------------------------------------

    private:
        CryptoPP::SecByteBlock key_;
    };

    std::unique_ptr<ILegacyEngine> CreateLegacyEngine(const LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case LEGACY_AES_128_CBC:
        case LEGACY_AES_192_CBC:
        case LEGACY_AES_256_CBC:
            return std::unique_ptr<ILegacyEngine>(new PaddedBlockEngine<CryptoPP::CBC_Mode<CryptoPP::AES>, true>());
        case LEGACY_AES_128_ECB:
        case LEGACY_AES_192_ECB:
        case LEGACY_AES_256_ECB:
            return std::unique_ptr<ILegacyEngine>(new PaddedBlockEngine<CryptoPP::ECB_Mode<CryptoPP::AES>, false>());
        case LEGACY_AES_128_CTR:
        case LEGACY_AES_192_CTR:
        case LEGACY_AES_256_CTR:
            return std::unique_ptr<ILegacyEngine>(new StreamLikeEngine<CryptoPP::CTR_Mode<CryptoPP::AES> >());
        case LEGACY_AES_128_CFB:
        case LEGACY_AES_192_CFB:
        case LEGACY_AES_256_CFB:
            return std::unique_ptr<ILegacyEngine>(new StreamLikeEngine<CryptoPP::CFB_Mode<CryptoPP::AES> >());
        case LEGACY_AES_128_OFB:
        case LEGACY_AES_192_OFB:
        case LEGACY_AES_256_OFB:
            return std::unique_ptr<ILegacyEngine>(new StreamLikeEngine<CryptoPP::OFB_Mode<CryptoPP::AES> >());
        default:
            return nullptr;
        }
    }
    // -----------------------------------------------------------------------------

    unsigned int LegacyKeySize(const LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case LEGACY_AES_128_CBC:
        case LEGACY_AES_128_CTR:
        case LEGACY_AES_128_CFB:
        case LEGACY_AES_128_OFB:
        case LEGACY_AES_128_ECB:
            return 16;
        case LEGACY_AES_192_CBC:
        case LEGACY_AES_192_CTR:
        case LEGACY_AES_192_CFB:
        case LEGACY_AES_192_OFB:
        case LEGACY_AES_192_ECB:
            return 24;
        case LEGACY_AES_256_CBC:
        case LEGACY_AES_256_CTR:
        case LEGACY_AES_256_CFB:
        case LEGACY_AES_256_OFB:
        case LEGACY_AES_256_ECB:
            return 32;
        default:
            return 0;
        }
    }
    // -----------------------------------------------------------------------------

    unsigned int LegacyIvSize(const LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case LEGACY_AES_128_ECB:
        case LEGACY_AES_192_ECB:
        case LEGACY_AES_256_ECB:
            return 0;
        default:
            return CRYPTOPP_PROVIDER_BLOCK_SIZE;
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

    typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256> >::Encryptor RsaOaepEncryptor;
    typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256> >::Decryptor RsaOaepDecryptor;
}

struct CCryptoPPProvider::Impl
{
    std::unique_ptr<IAeadEngine> aeadEngine;
    std::unique_ptr<ILegacyEngine> legacyEngine;
    bool legacySelected = false;
    unsigned int keySize = 0;
    unsigned int ivOrNonceSize = 0;
    unsigned int tagSize = 0;
    unsigned int blockSize = CRYPTOPP_PROVIDER_BLOCK_SIZE;

    unsigned int rsaKeyBits = 0;
    bool rsaKeyGenerated = false;
    CryptoPP::RSA::PrivateKey rsaPrivateKey;
    CryptoPP::RSA::PublicKey rsaPublicKey;

    // IHashService state. CryptoPP::HashTransformation is the common polymorphic base for every
    // hash class used below (MD5/SHA1/SHA2xx/SHA3xx/RIPEMD160 derive from it directly; BLAKE2b/
    // BLAKE2s derive from MessageAuthenticationCode, which is itself a HashTransformation, so the
    // same pointer type covers all 14 algorithms uniformly).
    std::unique_ptr<CryptoPP::HashTransformation> hashFunction;

    // ISignatureEngine state -- separate key material from rsaPrivateKey/rsaPublicKey above (that
    // pair is RSA-OAEP encryption; this is RSA-PSS/ECDSA/Ed25519 signing, a distinct key even when
    // both happen to be RSA). asymmetricModeIsSignature dispatches GenerateKeyPair() (shared with
    // IAsymmetricCipher, see the comment on its declaration in the header).
    bool asymmetricModeIsSignature = false;
    SignatureAlgorithm signatureAlgorithm = SIGNATURE_ECDSA_P256_SHA256;
    bool signatureKeyGenerated = false;
    unsigned int signatureSize = 0;
    CryptoPP::RSA::PrivateKey sigRsaPrivateKey;
    CryptoPP::RSA::PublicKey sigRsaPublicKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey ecdsaPrivateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey ecdsaPublicKey;
    std::unique_ptr<CryptoPP::ed25519Signer> ed25519SignerPtr;
    std::unique_ptr<CryptoPP::ed25519Verifier> ed25519VerifierPtr;
};

CCryptoPPProvider::~CCryptoPPProvider()
{
}
// -----------------------------------------------------------------------------

CCryptoPPProvider::CCryptoPPProvider() : impl_(new Impl())
{
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Initialize(void)
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

bool CCryptoPPProvider::SelectAlgorithm(const AeadAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<IAeadEngine> engine = CreateAeadEngine(algorithm);
        if (!engine)
        {
            return false;
        }

        impl_->aeadEngine = std::move(engine);
        impl_->legacyEngine.reset();
        impl_->legacySelected = false;
        impl_->keySize = AeadKeySize(algorithm);
        impl_->ivOrNonceSize = CRYPTOPP_PROVIDER_NONCE_SIZE;
        impl_->tagSize = CRYPTOPP_PROVIDER_TAG_SIZE;
        return impl_->keySize != 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::SelectAlgorithm(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        std::unique_ptr<ILegacyEngine> engine = CreateLegacyEngine(algorithm);
        if (!engine)
        {
            return false;
        }

        impl_->legacyEngine = std::move(engine);
        impl_->aeadEngine.reset();
        impl_->legacySelected = true;
        impl_->keySize = LegacyKeySize(algorithm);
        impl_->ivOrNonceSize = LegacyIvSize(algorithm);
        impl_->blockSize = CRYPTOPP_PROVIDER_BLOCK_SIZE;
        return impl_->keySize != 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetKeySize(void) const
{
    return impl_->keySize;
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (key == nullptr || keySize != impl_->keySize)
        {
            return false;
        }

        if (impl_->legacySelected)
        {
            if (!impl_->legacyEngine)
            {
                return false;
            }
            impl_->legacyEngine->SetKey(reinterpret_cast<const CryptoPP::byte*>(key), keySize);
        }
        else
        {
            if (!impl_->aeadEngine)
            {
                return false;
            }
            impl_->aeadEngine->SetKey(reinterpret_cast<const CryptoPP::byte*>(key), keySize);
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetNonceSize(void) const
{
    return impl_->ivOrNonceSize;
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetTagSize(void) const
{
    return impl_->tagSize;
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (!impl_->aeadEngine || nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        impl_->aeadEngine->Encrypt(reinterpret_cast<CryptoPP::byte*>(outputBuffer),
                                   reinterpret_cast<CryptoPP::byte*>(tag), tagSize,
                                   reinterpret_cast<const CryptoPP::byte*>(nonce), static_cast<int>(nonceSize),
                                   reinterpret_cast<const CryptoPP::byte*>(inputBuffer), inputBufferSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Decrypt(const unsigned char* nonce, const unsigned int nonceSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, const unsigned char* tag, const unsigned int tagSize, unsigned char* outputBuffer)
{
    try
    {
        if (!impl_->aeadEngine || nonce == nullptr || tag == nullptr ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        return impl_->aeadEngine->Decrypt(reinterpret_cast<CryptoPP::byte*>(outputBuffer),
                                          reinterpret_cast<const CryptoPP::byte*>(tag), tagSize,
                                          reinterpret_cast<const CryptoPP::byte*>(nonce), static_cast<int>(nonceSize),
                                          reinterpret_cast<const CryptoPP::byte*>(inputBuffer), inputBufferSize);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetIvSize(void) const
{
    return impl_->ivOrNonceSize;
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetBlockSize(void) const
{
    return impl_->blockSize;
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Encrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->legacyEngine || outputBufferSize == nullptr)
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

        const size_t required = impl_->legacyEngine->RequiredOutputSize(true, inputBufferSize);
        if (outputBufferCapacity == 0 || outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = static_cast<unsigned int>(required);
            return false;
        }

        size_t written = 0;
        const bool ok = impl_->legacyEngine->Encrypt(reinterpret_cast<const CryptoPP::byte*>(iv),
                                                      reinterpret_cast<const CryptoPP::byte*>(inputBuffer), inputBufferSize,
                                                      reinterpret_cast<CryptoPP::byte*>(outputBuffer), outputBufferCapacity, &written);
        *outputBufferSize = static_cast<unsigned int>(written);
        return ok;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Decrypt(const unsigned char* iv, const unsigned int ivSize, const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->legacyEngine || outputBufferSize == nullptr)
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

        const size_t required = impl_->legacyEngine->RequiredOutputSize(false, inputBufferSize);
        if (outputBufferCapacity == 0 || outputBuffer == nullptr || outputBufferCapacity < required)
        {
            *outputBufferSize = static_cast<unsigned int>(required);
            return false;
        }

        size_t written = 0;
        const bool ok = impl_->legacyEngine->Decrypt(reinterpret_cast<const CryptoPP::byte*>(iv),
                                                      reinterpret_cast<const CryptoPP::byte*>(inputBuffer), inputBufferSize,
                                                      reinterpret_cast<CryptoPP::byte*>(outputBuffer), outputBufferCapacity, &written);
        *outputBufferSize = static_cast<unsigned int>(written);
        return ok;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::DerivePasswordKey(const char* password, const unsigned int passwordSize, const unsigned char* salt, const unsigned int saltSize, const unsigned int iterationCount, unsigned char* derivedKey, const unsigned int derivedKeySize)
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

bool CCryptoPPProvider::GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize)
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

bool CCryptoPPProvider::SelectAlgorithm(const AsymmetricAlgorithm algorithm)
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
        impl_->asymmetricModeIsSignature = false;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::GenerateKeyPair(void)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        if (impl_->asymmetricModeIsSignature)
        {
            CryptoPP::AutoSeededRandomPool rng;

            switch (impl_->signatureAlgorithm)
            {
                case SIGNATURE_RSA_PSS_SHA256_2048:
                case SIGNATURE_RSA_PSS_SHA256_3072:
                case SIGNATURE_RSA_PSS_SHA256_4096:
                {
                    const unsigned int keyBits = SignatureRsaKeyBits(impl_->signatureAlgorithm);
                    CryptoPP::RSA::PrivateKey privateKey;
                    privateKey.GenerateRandomWithKeySize(rng, keyBits);
                    impl_->sigRsaPrivateKey = privateKey;
                    impl_->sigRsaPublicKey = CryptoPP::RSA::PublicKey(privateKey);
                    impl_->signatureSize = keyBits / 8;
                    break;
                }
                case SIGNATURE_ECDSA_P256_SHA256:
                {
                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
                    privateKey.Initialize(rng, CryptoPP::ASN1::secp256r1());
                    impl_->ecdsaPrivateKey = privateKey;
                    privateKey.MakePublicKey(impl_->ecdsaPublicKey);
                    impl_->signatureSize = 64;
                    break;
                }
                case SIGNATURE_ED25519:
                {
                    impl_->ed25519SignerPtr.reset(new CryptoPP::ed25519Signer(rng));
                    impl_->ed25519VerifierPtr.reset(new CryptoPP::ed25519Verifier(*impl_->ed25519SignerPtr));
                    impl_->signatureSize = 64;
                    break;
                }
                default:
                    return false;
            }

            impl_->signatureKeyGenerated = true;
            return true;
        }

        if (impl_->rsaKeyBits == 0)
        {
            return false;
        }

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, impl_->rsaKeyBits);

        impl_->rsaPrivateKey = privateKey;
        impl_->rsaPublicKey = CryptoPP::RSA::PublicKey(privateKey);
        impl_->rsaKeyGenerated = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetMaxPlaintextSize(void) const
{
    try
    {
        if (!impl_->rsaKeyGenerated)
        {
            return 0;
        }

        RsaOaepEncryptor encryptor(impl_->rsaPublicKey);
        return static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetCiphertextSize(void) const
{
    try
    {
        if (!impl_->rsaKeyGenerated)
        {
            return 0;
        }

        RsaOaepEncryptor encryptor(impl_->rsaPublicKey);
        return static_cast<unsigned int>(encryptor.FixedCiphertextLength());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Encrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->rsaKeyGenerated || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        RsaOaepEncryptor encryptor(impl_->rsaPublicKey);
        const size_t requiredSize = encryptor.FixedCiphertextLength();
        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = static_cast<unsigned int>(requiredSize);
            return false;
        }

        CryptoPP::AutoSeededRandomPool rng;
        encryptor.Encrypt(rng, reinterpret_cast<const CryptoPP::byte*>(inputBuffer), inputBufferSize,
                          reinterpret_cast<CryptoPP::byte*>(outputBuffer));
        *outputBufferSize = static_cast<unsigned int>(requiredSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Decrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize, unsigned char* outputBuffer, const unsigned int outputBufferCapacity, unsigned int* outputBufferSize)
{
    try
    {
        if (!impl_->rsaKeyGenerated || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        RsaOaepDecryptor decryptor(impl_->rsaPrivateKey);
        const size_t requiredSize = decryptor.FixedMaxPlaintextLength();
        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = static_cast<unsigned int>(requiredSize);
            return false;
        }

        CryptoPP::AutoSeededRandomPool rng;
        const CryptoPP::DecodingResult result = decryptor.Decrypt(rng,
            reinterpret_cast<const CryptoPP::byte*>(inputBuffer), inputBufferSize,
            reinterpret_cast<CryptoPP::byte*>(outputBuffer));
        if (!result.isValidCoding)
        {
            return false;
        }

        *outputBufferSize = static_cast<unsigned int>(result.messageLength);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetMacSize(void) const
{
    return 32; // HMAC-SHA256
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::ComputeMac(const unsigned char* key, const unsigned int keySize, const unsigned char* data, const unsigned int dataSize, unsigned char* mac, const unsigned int macSize)
{
    try
    {
        if (key == nullptr || keySize == 0 || mac == nullptr || macSize != 32 ||
            (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        CryptoPP::HMAC<CryptoPP::SHA256> hmac(reinterpret_cast<const CryptoPP::byte*>(key), keySize);
        hmac.CalculateDigest(reinterpret_cast<CryptoPP::byte*>(mac),
                             reinterpret_cast<const CryptoPP::byte*>(data), dataSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::SelectAlgorithm(const HashAlgorithm algorithm)
{
    try
    {
        if (!impl_)
        {
            return false;
        }

        std::unique_ptr<CryptoPP::HashTransformation> hashFunction;
        switch (algorithm)
        {
            case HASH_MD5:        hashFunction.reset(new CryptoPP::MD5());        break;
            case HASH_SHA1:       hashFunction.reset(new CryptoPP::SHA1());       break;
            case HASH_SHA224:     hashFunction.reset(new CryptoPP::SHA224());     break;
            case HASH_SHA256:     hashFunction.reset(new CryptoPP::SHA256());     break;
            case HASH_SHA384:     hashFunction.reset(new CryptoPP::SHA384());     break;
            case HASH_SHA512:     hashFunction.reset(new CryptoPP::SHA512());     break;
            case HASH_SHA3_224:   hashFunction.reset(new CryptoPP::SHA3_224());   break;
            case HASH_SHA3_256:   hashFunction.reset(new CryptoPP::SHA3_256());   break;
            case HASH_SHA3_384:   hashFunction.reset(new CryptoPP::SHA3_384());   break;
            case HASH_SHA3_512:   hashFunction.reset(new CryptoPP::SHA3_512());   break;
            case HASH_BLAKE2B:    hashFunction.reset(new CryptoPP::BLAKE2b());    break; // 64-byte default
            case HASH_BLAKE2S:    hashFunction.reset(new CryptoPP::BLAKE2s());    break; // 32-byte default
            case HASH_RIPEMD160:  hashFunction.reset(new CryptoPP::RIPEMD160());  break;
            // HASH_SHA512_256: no CryptoPP class for the truncated SHA-512/256 variant -- correctly
            // unsupported here (falls through to default).
            default:
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

unsigned int CCryptoPPProvider::GetHashSize(void) const
{
    try
    {
        return (impl_ && impl_->hashFunction) ? impl_->hashFunction->DigestSize() : 0;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::ComputeHash(const unsigned char* data, const unsigned int dataSize, unsigned char* hash, const unsigned int hashSize)
{
    try
    {
        if (!impl_ || !impl_->hashFunction || hash == nullptr ||
            hashSize < impl_->hashFunction->DigestSize() || (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        impl_->hashFunction->CalculateDigest(reinterpret_cast<CryptoPP::byte*>(hash),
                                             reinterpret_cast<const CryptoPP::byte*>(data), dataSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Init(void)
{
    try
    {
        if (!impl_ || !impl_->hashFunction)
        {
            return false;
        }

        impl_->hashFunction->Restart();
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Update(const unsigned char* data, const unsigned int dataSize)
{
    try
    {
        if (!impl_ || !impl_->hashFunction || (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        impl_->hashFunction->Update(reinterpret_cast<const CryptoPP::byte*>(data), dataSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Final(unsigned char* hash, const unsigned int hashSize)
{
    try
    {
        if (!impl_ || !impl_->hashFunction || hash == nullptr || hashSize < impl_->hashFunction->DigestSize())
        {
            return false;
        }

        impl_->hashFunction->Final(reinterpret_cast<CryptoPP::byte*>(hash));
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::SelectAlgorithm(const SignatureAlgorithm algorithm)
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
            case SIGNATURE_ED25519:
                break;
            default:
                return false;
        }

        impl_->signatureAlgorithm = algorithm;
        impl_->signatureKeyGenerated = false;
        impl_->signatureSize = 0;
        impl_->asymmetricModeIsSignature = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CCryptoPPProvider::GetSignatureSize(void) const
{
    return (impl_ && impl_->signatureKeyGenerated) ? impl_->signatureSize : 0;
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Sign(const unsigned char* data, const unsigned int dataSize, unsigned char* signature, const unsigned int signatureSize)
{
    try
    {
        if (!impl_ || !impl_->signatureKeyGenerated || signature == nullptr || signatureSize < impl_->signatureSize ||
            (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        CryptoPP::AutoSeededRandomPool rng;
        size_t actualLength = 0;

        switch (impl_->signatureAlgorithm)
        {
            case SIGNATURE_RSA_PSS_SHA256_2048:
            case SIGNATURE_RSA_PSS_SHA256_3072:
            case SIGNATURE_RSA_PSS_SHA256_4096:
            {
                CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(impl_->sigRsaPrivateKey);
                actualLength = signer.SignMessage(rng, data, dataSize, signature);
                break;
            }
            case SIGNATURE_ECDSA_P256_SHA256:
            {
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(impl_->ecdsaPrivateKey);
                actualLength = signer.SignMessage(rng, data, dataSize, signature);
                break;
            }
            case SIGNATURE_ED25519:
            {
                if (!impl_->ed25519SignerPtr)
                {
                    return false;
                }
                actualLength = impl_->ed25519SignerPtr->SignMessage(rng, data, dataSize, signature);
                break;
            }
            default:
                return false;
        }

        return actualLength == impl_->signatureSize;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CCryptoPPProvider::Verify(const unsigned char* data, const unsigned int dataSize, const unsigned char* signature, const unsigned int signatureSize)
{
    try
    {
        if (!impl_ || !impl_->signatureKeyGenerated || signature == nullptr || signatureSize != impl_->signatureSize ||
            (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        switch (impl_->signatureAlgorithm)
        {
            case SIGNATURE_RSA_PSS_SHA256_2048:
            case SIGNATURE_RSA_PSS_SHA256_3072:
            case SIGNATURE_RSA_PSS_SHA256_4096:
            {
                CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier verifier(impl_->sigRsaPublicKey);
                return verifier.VerifyMessage(data, dataSize, signature, signatureSize);
            }
            case SIGNATURE_ECDSA_P256_SHA256:
            {
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(impl_->ecdsaPublicKey);
                return verifier.VerifyMessage(data, dataSize, signature, signatureSize);
            }
            case SIGNATURE_ED25519:
            {
                if (!impl_->ed25519VerifierPtr)
                {
                    return false;
                }
                return impl_->ed25519VerifierPtr->VerifyMessage(data, dataSize, signature, signatureSize);
            }
            default:
                return false;
        }
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

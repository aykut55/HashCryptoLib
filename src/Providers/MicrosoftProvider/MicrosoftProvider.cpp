#include "MicrosoftProvider.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")

#include <cwchar>

namespace CryptoApiNS
{

namespace
{
    // Windows CNG/BCrypt only ships AES natively, and only these chaining modes. There is no
    // BCRYPT_CHAIN_MODE_CTR / _OFB, and no EAX/SIV/GCM-SIV/ChaCha20-Poly1305/Twofish/Serpent/
    // Camellia support at all, so those combinations correctly report unsupported below.

    const wchar_t* AeadChainingMode(AeadAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case AEAD_AES_128_GCM:
            case AEAD_AES_192_GCM:
            case AEAD_AES_256_GCM:
                return BCRYPT_CHAIN_MODE_GCM;
            case AEAD_AES_128_CCM:
            case AEAD_AES_192_CCM:
            case AEAD_AES_256_CCM:
                return BCRYPT_CHAIN_MODE_CCM;
            default:
                return nullptr;
        }
    }
    // -------------------------------------------------------------------------

    unsigned int AeadKeySize(AeadAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case AEAD_AES_128_GCM:
            case AEAD_AES_128_CCM:
                return 16;
            case AEAD_AES_192_GCM:
            case AEAD_AES_192_CCM:
                return 24;
            case AEAD_AES_256_GCM:
            case AEAD_AES_256_CCM:
                return 32;
            default:
                return 0;
        }
    }
    // -------------------------------------------------------------------------

    // BCRYPT_CHAIN_MODE_* return value: the chaining mode to set via BCryptSetProperty.
    // nullptr has two different meanings depending on the algorithm, disambiguated by
    // LegacyIsSupported(): RC4 genuinely has no chaining-mode property to set (pure stream
    // cipher), while CTR/OFB are simply not available in BCrypt at all.
    const wchar_t* LegacyChainingMode(LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case LEGACY_AES_128_CBC:
            case LEGACY_AES_192_CBC:
            case LEGACY_AES_256_CBC:
            case LEGACY_RC2_CBC:
            case LEGACY_DES_CBC:
            case LEGACY_3DES_CBC:
                return BCRYPT_CHAIN_MODE_CBC;
            case LEGACY_AES_128_CFB:
            case LEGACY_AES_192_CFB:
            case LEGACY_AES_256_CFB:
                return BCRYPT_CHAIN_MODE_CFB;
            case LEGACY_AES_128_ECB:
            case LEGACY_AES_192_ECB:
            case LEGACY_AES_256_ECB:
            case LEGACY_RC2_ECB:
            case LEGACY_DES_ECB:
            case LEGACY_3DES_ECB:
                return BCRYPT_CHAIN_MODE_ECB;
            default:
                return nullptr;
        }
    }
    // -------------------------------------------------------------------------

    bool LegacyIsSupported(LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case LEGACY_AES_128_CBC:
            case LEGACY_AES_192_CBC:
            case LEGACY_AES_256_CBC:
            case LEGACY_AES_128_CFB:
            case LEGACY_AES_192_CFB:
            case LEGACY_AES_256_CFB:
            case LEGACY_AES_128_ECB:
            case LEGACY_AES_192_ECB:
            case LEGACY_AES_256_ECB:
            case LEGACY_RC2_CBC:
            case LEGACY_RC2_ECB:
            case LEGACY_DES_CBC:
            case LEGACY_DES_ECB:
            case LEGACY_3DES_CBC:
            case LEGACY_3DES_ECB:
            case LEGACY_RC4:
                return true;
            default:
                return false; // CTR/OFB: no native BCrypt chaining mode exists
        }
    }
    // -------------------------------------------------------------------------

    const wchar_t* LegacyBaseAlgorithm(LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case LEGACY_RC2_CBC:
            case LEGACY_RC2_ECB:
                return BCRYPT_RC2_ALGORITHM;
            case LEGACY_RC4:
                return BCRYPT_RC4_ALGORITHM;
            case LEGACY_DES_CBC:
            case LEGACY_DES_ECB:
                return BCRYPT_DES_ALGORITHM;
            case LEGACY_3DES_CBC:
            case LEGACY_3DES_ECB:
                return BCRYPT_3DES_ALGORITHM;
            default:
                return BCRYPT_AES_ALGORITHM;
        }
    }
    // -------------------------------------------------------------------------

    unsigned int LegacyKeySize(LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case LEGACY_AES_128_CBC:
            case LEGACY_AES_128_CFB:
            case LEGACY_AES_128_ECB:
                return 16;
            case LEGACY_AES_192_CBC:
            case LEGACY_AES_192_CFB:
            case LEGACY_AES_192_ECB:
                return 24;
            case LEGACY_AES_256_CBC:
            case LEGACY_AES_256_CFB:
            case LEGACY_AES_256_ECB:
                return 32;
            case LEGACY_RC2_CBC:
            case LEGACY_RC2_ECB:
                return 16; // 128-bit effective key length (CNG's RC2 default)
            case LEGACY_RC4:
                return 16; // 128-bit; RC4 accepts variable lengths, this is our fixed choice
            case LEGACY_DES_CBC:
            case LEGACY_DES_ECB:
                return 8; // 56-bit effective + parity, packed into 8 raw bytes
            case LEGACY_3DES_CBC:
            case LEGACY_3DES_ECB:
                return 24; // 3-key EDE3 (168-bit effective)
            default:
                return 0;
        }
    }
    // -------------------------------------------------------------------------

    bool LegacyIsPadded(LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case LEGACY_AES_128_CBC:
            case LEGACY_AES_192_CBC:
            case LEGACY_AES_256_CBC:
            case LEGACY_AES_128_ECB:
            case LEGACY_AES_192_ECB:
            case LEGACY_AES_256_ECB:
            case LEGACY_RC2_CBC:
            case LEGACY_RC2_ECB:
            case LEGACY_DES_CBC:
            case LEGACY_DES_ECB:
            case LEGACY_3DES_CBC:
            case LEGACY_3DES_ECB:
                return true;
            default:
                return false; // CFB/OFB/CTR-style streaming and RC4 need no padding
        }
    }
    // -------------------------------------------------------------------------

    bool LegacyHasIv(LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case LEGACY_AES_128_ECB:
            case LEGACY_AES_192_ECB:
            case LEGACY_AES_256_ECB:
            case LEGACY_RC2_ECB:
            case LEGACY_DES_ECB:
            case LEGACY_3DES_ECB:
            case LEGACY_RC4:
                return false;
            default:
                return true;
        }
    }
    // -------------------------------------------------------------------------

    unsigned int LegacyBlockSize(LegacySymmetricAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case LEGACY_RC2_CBC:
            case LEGACY_RC2_ECB:
            case LEGACY_DES_CBC:
            case LEGACY_DES_ECB:
            case LEGACY_3DES_CBC:
            case LEGACY_3DES_ECB:
                return 8;
            case LEGACY_RC4:
                return 1; // stream cipher, no real block
            default:
                return 16; // AES
        }
    }
    // -------------------------------------------------------------------------

    unsigned int LegacyIvSize(LegacySymmetricAlgorithm algorithm)
    {
        if (!LegacyHasIv(algorithm))
        {
            return 0;
        }

        return LegacyBlockSize(algorithm);
    }
    // -------------------------------------------------------------------------

    unsigned int AsymmetricKeyBits(AsymmetricAlgorithm algorithm)
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
    // -------------------------------------------------------------------------

    // Windows CNG has no BCRYPT_SHA224/SHA3_224/SHA512_256/BLAKE2B/BLAKE2S/RIPEMD160_ALGORITHM
    // identifiers at all (confirmed against the vendored Windows SDK's bcrypt.h), so those five
    // correctly return nullptr = unsupported here. SHA3-256/384/512 exist as identifiers but only
    // actually open successfully on Windows 11 24H2+/Server 2025+; SelectAlgorithm() below handles
    // that at runtime via BCryptOpenAlgorithmProvider's return value, not here.
    const wchar_t* HashAlgorithmName(HashAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case HASH_MD5:      return BCRYPT_MD5_ALGORITHM;
            case HASH_SHA1:     return BCRYPT_SHA1_ALGORITHM;
            case HASH_SHA256:   return BCRYPT_SHA256_ALGORITHM;
            case HASH_SHA384:   return BCRYPT_SHA384_ALGORITHM;
            case HASH_SHA512:   return BCRYPT_SHA512_ALGORITHM;
            case HASH_SHA3_256: return BCRYPT_SHA3_256_ALGORITHM;
            case HASH_SHA3_384: return BCRYPT_SHA3_384_ALGORITHM;
            case HASH_SHA3_512: return BCRYPT_SHA3_512_ALGORITHM;
            default:            return nullptr;
        }
    }
}
// -----------------------------------------------------------------------------

CMicrosoftProvider::~CMicrosoftProvider()
{
    try
    {
        if (keyHandle_ != nullptr)
        {
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_));
        }

        if (algorithmHandle_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(algorithmHandle_), 0);
        }

        if (!keyObject_.empty())
        {
            SecureZeroMemory(&keyObject_[0], keyObject_.size());
        }

        if (rsaKeyHandle_ != nullptr)
        {
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(rsaKeyHandle_));
        }

        if (rsaAlgorithmHandle_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(rsaAlgorithmHandle_), 0);
        }

        if (hashObjectHandle_ != nullptr)
        {
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hashObjectHandle_));
        }

        if (hashAlgorithmHandle_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(hashAlgorithmHandle_), 0);
        }

        if (!hashObjectBuffer_.empty())
        {
            SecureZeroMemory(&hashObjectBuffer_[0], hashObjectBuffer_.size());
        }
    }
    catch (...)
    {
    }
}
// -----------------------------------------------------------------------------

CMicrosoftProvider::CMicrosoftProvider()
    : algorithmHandle_(nullptr),
      keyHandle_(nullptr),
      keyObjectSize_(0),
      legacySelected_(false),
      isPadded_(false),
      keySize_(0),
      ivOrNonceSize_(0),
      tagSize_(0),
      blockSize_(16),
      rsaAlgorithmHandle_(nullptr),
      rsaKeyHandle_(nullptr),
      rsaKeyBits_(0),
      hashAlgorithmHandle_(nullptr),
      hashObjectHandle_(nullptr),
      hashOutputSize_(0)
{
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Initialize(void)
{
    try
    {
        BCRYPT_ALG_HANDLE probeHandle = nullptr;
        if (BCryptOpenAlgorithmProvider(&probeHandle, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0)
        {
            return false;
        }

        BCryptCloseAlgorithmProvider(probeHandle, 0);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::SelectAlgorithm(const AeadAlgorithm algorithm)
{
    try
    {
        const wchar_t* chainingMode = AeadChainingMode(algorithm);
        if (chainingMode == nullptr)
        {
            return false;
        }

        BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
        if (BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0)
        {
            return false;
        }

        if (BCryptSetProperty(algorithmHandle,
                              BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(chainingMode)),
                              static_cast<ULONG>((wcslen(chainingMode) + 1) * sizeof(wchar_t)),
                              0) < 0)
        {
            BCryptCloseAlgorithmProvider(algorithmHandle, 0);
            return false;
        }

        ULONG keyObjectSize = 0;
        ULONG resultSize = 0;
        if (BCryptGetProperty(algorithmHandle,
                              BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&keyObjectSize),
                              sizeof(keyObjectSize),
                              &resultSize,
                              0) < 0 ||
            resultSize != sizeof(keyObjectSize) ||
            keyObjectSize == 0)
        {
            BCryptCloseAlgorithmProvider(algorithmHandle, 0);
            return false;
        }

        if (keyHandle_ != nullptr)
        {
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_));
            keyHandle_ = nullptr;
        }

        if (algorithmHandle_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(algorithmHandle_), 0);
        }

        algorithmHandle_ = algorithmHandle;
        keyObjectSize_ = keyObjectSize;
        keyObject_.assign(keyObjectSize, 0);

        legacySelected_ = false;
        isPadded_ = false;
        keySize_ = AeadKeySize(algorithm);
        ivOrNonceSize_ = 12;
        tagSize_ = 16;
        blockSize_ = 16;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::SelectAlgorithm(const LegacySymmetricAlgorithm algorithm)
{
    try
    {
        if (!LegacyIsSupported(algorithm))
        {
            return false;
        }

        const wchar_t* baseAlgorithm = LegacyBaseAlgorithm(algorithm);
        const wchar_t* chainingMode = LegacyChainingMode(algorithm); // nullptr for RC4: no property to set

        BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
        if (BCryptOpenAlgorithmProvider(&algorithmHandle, baseAlgorithm, nullptr, 0) < 0)
        {
            return false;
        }

        if (chainingMode != nullptr &&
            BCryptSetProperty(algorithmHandle,
                              BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(chainingMode)),
                              static_cast<ULONG>((wcslen(chainingMode) + 1) * sizeof(wchar_t)),
                              0) < 0)
        {
            BCryptCloseAlgorithmProvider(algorithmHandle, 0);
            return false;
        }

        ULONG keyObjectSize = 0;
        ULONG resultSize = 0;
        if (BCryptGetProperty(algorithmHandle,
                              BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&keyObjectSize),
                              sizeof(keyObjectSize),
                              &resultSize,
                              0) < 0 ||
            resultSize != sizeof(keyObjectSize) ||
            keyObjectSize == 0)
        {
            BCryptCloseAlgorithmProvider(algorithmHandle, 0);
            return false;
        }

        if (keyHandle_ != nullptr)
        {
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_));
            keyHandle_ = nullptr;
        }

        if (algorithmHandle_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(algorithmHandle_), 0);
        }

        algorithmHandle_ = algorithmHandle;
        keyObjectSize_ = keyObjectSize;
        keyObject_.assign(keyObjectSize, 0);

        legacySelected_ = true;
        isPadded_ = LegacyIsPadded(algorithm);
        keySize_ = LegacyKeySize(algorithm);
        ivOrNonceSize_ = LegacyIvSize(algorithm);
        tagSize_ = 0;
        blockSize_ = LegacyBlockSize(algorithm);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetKeySize(void) const
{
    return keySize_;
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetNonceSize(void) const
{
    return ivOrNonceSize_;
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetTagSize(void) const
{
    return tagSize_;
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetIvSize(void) const
{
    return ivOrNonceSize_;
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetBlockSize(void) const
{
    return blockSize_;
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (key == nullptr || keySize != keySize_ || algorithmHandle_ == nullptr)
        {
            return false;
        }

        // The key object buffer IS the key handle's backing storage for its whole lifetime (per
        // BCryptGenerateSymmetricKey's contract), so any prior handle using keyObject_ must be
        // destroyed BEFORE that memory is reused for a new key -- otherwise BCryptGenerateSymmetricKey
        // corrupts the still-alive old handle's internal state out from under it. This matters
        // whenever SetKey() is called more than once on the same instance (e.g. RC4's keystream
        // must be reset by re-keying between an Encrypt and a following Decrypt).
        if (keyHandle_ != nullptr)
        {
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_));
            keyHandle_ = nullptr;
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        if (BCryptGenerateSymmetricKey(static_cast<BCRYPT_ALG_HANDLE>(algorithmHandle_),
                                       &keyHandle,
                                       &keyObject_[0],
                                       keyObjectSize_,
                                       const_cast<PUCHAR>(key),
                                       keySize,
                                       0) < 0)
        {
            return false;
        }

        keyHandle_ = keyHandle;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize,
                              const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                              unsigned char* outputBuffer,
                              unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (nonce == nullptr || tag == nullptr || keyHandle_ == nullptr || legacySelected_ ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(nonce);
        authInfo.cbNonce = nonceSize;
        authInfo.pbAuthData = nullptr;
        authInfo.cbAuthData = 0;
        authInfo.pbTag = tag;
        authInfo.cbTag = tagSize;

        ULONG outputSize = 0;
        return BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_),
                             const_cast<PUCHAR>(inputBuffer),
                             inputBufferSize,
                             &authInfo,
                             nullptr,
                             0,
                             outputBuffer,
                             inputBufferSize,
                             &outputSize,
                             0) >= 0 &&
               outputSize == inputBufferSize;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Decrypt(const unsigned char* nonce, const unsigned int nonceSize,
                              const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                              const unsigned char* tag, const unsigned int tagSize,
                              unsigned char* outputBuffer)
{
    try
    {
        if (nonce == nullptr || tag == nullptr || keyHandle_ == nullptr || legacySelected_ ||
            (inputBufferSize > 0 && (inputBuffer == nullptr || outputBuffer == nullptr)))
        {
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(nonce);
        authInfo.cbNonce = nonceSize;
        authInfo.pbAuthData = nullptr;
        authInfo.cbAuthData = 0;
        authInfo.pbTag = const_cast<PUCHAR>(tag);
        authInfo.cbTag = tagSize;

        ULONG outputSize = 0;
        return BCryptDecrypt(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_),
                             const_cast<PUCHAR>(inputBuffer),
                             inputBufferSize,
                             &authInfo,
                             nullptr,
                             0,
                             outputBuffer,
                             inputBufferSize,
                             &outputSize,
                             0) >= 0 &&
               outputSize == inputBufferSize;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Encrypt(const unsigned char* iv, const unsigned int ivSize,
                              const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                              unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                              unsigned int* outputBufferSize)
{
    try
    {
        if (keyHandle_ == nullptr || !legacySelected_ || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr) ||
            (ivOrNonceSize_ > 0 && (iv == nullptr || ivSize != ivOrNonceSize_)))
        {
            return false;
        }

        const ULONG flags = isPadded_ ? BCRYPT_BLOCK_PADDING : 0;
        std::vector<unsigned char> ivCopy;
        if (ivOrNonceSize_ > 0)
        {
            ivCopy.assign(iv, iv + ivOrNonceSize_);
        }

        ULONG requiredSize = 0;
        if (BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_),
                          const_cast<PUCHAR>(inputBuffer), inputBufferSize,
                          nullptr,
                          ivOrNonceSize_ > 0 ? &ivCopy[0] : nullptr, ivOrNonceSize_,
                          nullptr, 0,
                          &requiredSize, flags) < 0)
        {
            return false;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = requiredSize;
            return false;
        }

        if (ivOrNonceSize_ > 0)
        {
            ivCopy.assign(iv, iv + ivOrNonceSize_);
        }

        ULONG actualSize = 0;
        if (BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_),
                          const_cast<PUCHAR>(inputBuffer), inputBufferSize,
                          nullptr,
                          ivOrNonceSize_ > 0 ? &ivCopy[0] : nullptr, ivOrNonceSize_,
                          outputBuffer, outputBufferCapacity,
                          &actualSize, flags) < 0)
        {
            return false;
        }

        *outputBufferSize = actualSize;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Decrypt(const unsigned char* iv, const unsigned int ivSize,
                              const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                              unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                              unsigned int* outputBufferSize)
{
    try
    {
        if (keyHandle_ == nullptr || !legacySelected_ || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr) ||
            (ivOrNonceSize_ > 0 && (iv == nullptr || ivSize != ivOrNonceSize_)))
        {
            return false;
        }

        const ULONG flags = isPadded_ ? BCRYPT_BLOCK_PADDING : 0;
        std::vector<unsigned char> ivCopy;
        if (ivOrNonceSize_ > 0)
        {
            ivCopy.assign(iv, iv + ivOrNonceSize_);
        }

        ULONG requiredSize = 0;
        if (BCryptDecrypt(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_),
                          const_cast<PUCHAR>(inputBuffer), inputBufferSize,
                          nullptr,
                          ivOrNonceSize_ > 0 ? &ivCopy[0] : nullptr, ivOrNonceSize_,
                          nullptr, 0,
                          &requiredSize, flags) < 0)
        {
            return false;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = requiredSize;
            return false;
        }

        if (ivOrNonceSize_ > 0)
        {
            ivCopy.assign(iv, iv + ivOrNonceSize_);
        }

        ULONG actualSize = 0;
        if (BCryptDecrypt(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_),
                          const_cast<PUCHAR>(inputBuffer), inputBufferSize,
                          nullptr,
                          ivOrNonceSize_ > 0 ? &ivCopy[0] : nullptr, ivOrNonceSize_,
                          outputBuffer, outputBufferCapacity,
                          &actualSize, flags) < 0)
        {
            return false;
        }

        *outputBufferSize = actualSize;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::DerivePasswordKey(const char* password, const unsigned int passwordSize,
                                        const unsigned char* salt, const unsigned int saltSize,
                                        const unsigned int iterationCount,
                                        unsigned char* derivedKey, const unsigned int derivedKeySize)
{
    try
    {
        if (password == nullptr || salt == nullptr || derivedKey == nullptr)
        {
            return false;
        }

        BCRYPT_ALG_HANDLE hashAlgorithm = nullptr;
        if (BCryptOpenAlgorithmProvider(&hashAlgorithm,
                                        BCRYPT_SHA256_ALGORITHM,
                                        nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
        {
            return false;
        }

        const NTSTATUS status = BCryptDeriveKeyPBKDF2(hashAlgorithm,
                                                       reinterpret_cast<PUCHAR>(const_cast<char*>(password)),
                                                       passwordSize,
                                                       const_cast<PUCHAR>(salt),
                                                       saltSize,
                                                       iterationCount,
                                                       derivedKey,
                                                       derivedKeySize,
                                                       0);
        BCryptCloseAlgorithmProvider(hashAlgorithm, 0);
        return status >= 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize)
{
    try
    {
        if (buffer == nullptr && bufferSize > 0)
        {
            return false;
        }

        return BCryptGenRandom(nullptr, buffer, bufferSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::SelectAlgorithm(const AsymmetricAlgorithm algorithm)
{
    try
    {
        const unsigned int keyBits = AsymmetricKeyBits(algorithm);
        if (keyBits == 0)
        {
            return false;
        }

        BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
        if (BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_RSA_ALGORITHM, nullptr, 0) < 0)
        {
            return false;
        }

        if (rsaKeyHandle_ != nullptr)
        {
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(rsaKeyHandle_));
            rsaKeyHandle_ = nullptr;
        }

        if (rsaAlgorithmHandle_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(rsaAlgorithmHandle_), 0);
        }

        rsaAlgorithmHandle_ = algorithmHandle;
        rsaKeyBits_ = keyBits;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::GenerateKeyPair(void)
{
    try
    {
        if (rsaAlgorithmHandle_ == nullptr || rsaKeyBits_ == 0)
        {
            return false;
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        if (BCryptGenerateKeyPair(static_cast<BCRYPT_ALG_HANDLE>(rsaAlgorithmHandle_),
                                  &keyHandle, rsaKeyBits_, 0) < 0)
        {
            return false;
        }

        if (BCryptFinalizeKeyPair(keyHandle, 0) < 0)
        {
            BCryptDestroyKey(keyHandle);
            return false;
        }

        if (rsaKeyHandle_ != nullptr)
        {
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(rsaKeyHandle_));
        }

        rsaKeyHandle_ = keyHandle;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetMaxPlaintextSize(void) const
{
    const unsigned int keyBytes = rsaKeyBits_ / 8;
    const unsigned int oaepOverhead = 2u * 32u + 2u; // SHA-256 OAEP: 2*hashLen + 2
    return keyBytes > oaepOverhead ? keyBytes - oaepOverhead : 0;
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetCiphertextSize(void) const
{
    return rsaKeyBits_ / 8;
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Encrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                                unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                                unsigned int* outputBufferSize)
{
    try
    {
        if (rsaKeyHandle_ == nullptr || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        BCRYPT_OAEP_PADDING_INFO paddingInfo;
        paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        paddingInfo.pbLabel = nullptr;
        paddingInfo.cbLabel = 0;

        ULONG requiredSize = 0;
        if (BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(rsaKeyHandle_),
                          const_cast<PUCHAR>(inputBuffer), inputBufferSize,
                          &paddingInfo, nullptr, 0,
                          nullptr, 0, &requiredSize, BCRYPT_PAD_OAEP) < 0)
        {
            return false;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = requiredSize;
            return false;
        }

        ULONG actualSize = 0;
        if (BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(rsaKeyHandle_),
                          const_cast<PUCHAR>(inputBuffer), inputBufferSize,
                          &paddingInfo, nullptr, 0,
                          outputBuffer, outputBufferCapacity, &actualSize, BCRYPT_PAD_OAEP) < 0)
        {
            return false;
        }

        *outputBufferSize = actualSize;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Decrypt(const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                                unsigned char* outputBuffer, const unsigned int outputBufferCapacity,
                                unsigned int* outputBufferSize)
{
    try
    {
        if (rsaKeyHandle_ == nullptr || outputBufferSize == nullptr ||
            (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return false;
        }

        BCRYPT_OAEP_PADDING_INFO paddingInfo;
        paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        paddingInfo.pbLabel = nullptr;
        paddingInfo.cbLabel = 0;

        ULONG requiredSize = 0;
        if (BCryptDecrypt(static_cast<BCRYPT_KEY_HANDLE>(rsaKeyHandle_),
                          const_cast<PUCHAR>(inputBuffer), inputBufferSize,
                          &paddingInfo, nullptr, 0,
                          nullptr, 0, &requiredSize, BCRYPT_PAD_OAEP) < 0)
        {
            return false;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < requiredSize)
        {
            *outputBufferSize = requiredSize;
            return false;
        }

        ULONG actualSize = 0;
        if (BCryptDecrypt(static_cast<BCRYPT_KEY_HANDLE>(rsaKeyHandle_),
                          const_cast<PUCHAR>(inputBuffer), inputBufferSize,
                          &paddingInfo, nullptr, 0,
                          outputBuffer, outputBufferCapacity, &actualSize, BCRYPT_PAD_OAEP) < 0)
        {
            return false;
        }

        *outputBufferSize = actualSize;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetMacSize(void) const
{
    return 32; // HMAC-SHA256
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::ComputeMac(const unsigned char* key, const unsigned int keySize, const unsigned char* data, const unsigned int dataSize, unsigned char* mac, const unsigned int macSize)
{
    try
    {
        if (key == nullptr || keySize == 0 || mac == nullptr || macSize != 32 ||
            (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        BCRYPT_ALG_HANDLE hmacAlgorithm = nullptr;
        if (BCryptOpenAlgorithmProvider(&hmacAlgorithm,
                                        BCRYPT_SHA256_ALGORITHM,
                                        nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
        {
            return false;
        }

        const NTSTATUS status = BCryptHash(hmacAlgorithm,
                                           const_cast<PUCHAR>(key), keySize,
                                           const_cast<PUCHAR>(data), dataSize,
                                           mac, macSize);

        BCryptCloseAlgorithmProvider(hmacAlgorithm, 0);
        return status >= 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::SelectAlgorithm(const HashAlgorithm algorithm)
{
    try
    {
        const wchar_t* algorithmName = HashAlgorithmName(algorithm);
        if (algorithmName == nullptr)
        {
            return false;
        }

        BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
        if (BCryptOpenAlgorithmProvider(&algorithmHandle, algorithmName, nullptr, 0) < 0)
        {
            return false;
        }

        ULONG hashOutputSize = 0;
        ULONG hashObjectSize = 0;
        ULONG resultSize = 0;
        if (BCryptGetProperty(algorithmHandle, BCRYPT_HASH_LENGTH,
                              reinterpret_cast<PUCHAR>(&hashOutputSize), sizeof(hashOutputSize),
                              &resultSize, 0) < 0 || resultSize != sizeof(hashOutputSize) || hashOutputSize == 0 ||
            BCryptGetProperty(algorithmHandle, BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&hashObjectSize), sizeof(hashObjectSize),
                              &resultSize, 0) < 0 || resultSize != sizeof(hashObjectSize) || hashObjectSize == 0)
        {
            BCryptCloseAlgorithmProvider(algorithmHandle, 0);
            return false;
        }

        if (hashObjectHandle_ != nullptr)
        {
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hashObjectHandle_));
            hashObjectHandle_ = nullptr;
        }

        if (hashAlgorithmHandle_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(hashAlgorithmHandle_), 0);
        }

        hashAlgorithmHandle_ = algorithmHandle;
        hashOutputSize_ = hashOutputSize;
        hashObjectBuffer_.assign(hashObjectSize, 0);

        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CMicrosoftProvider::GetHashSize(void) const
{
    return hashOutputSize_;
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::ComputeHash(const unsigned char* data, const unsigned int dataSize, unsigned char* hash, const unsigned int hashSize)
{
    return Init() && Update(data, dataSize) && Final(hash, hashSize);
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Init(void)
{
    try
    {
        if (hashAlgorithmHandle_ == nullptr || hashObjectBuffer_.empty())
        {
            return false;
        }

        if (hashObjectHandle_ != nullptr)
        {
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hashObjectHandle_));
            hashObjectHandle_ = nullptr;
        }

        BCRYPT_HASH_HANDLE hashHandle = nullptr;
        if (BCryptCreateHash(static_cast<BCRYPT_ALG_HANDLE>(hashAlgorithmHandle_),
                             &hashHandle,
                             &hashObjectBuffer_[0], static_cast<ULONG>(hashObjectBuffer_.size()),
                             nullptr, 0, 0) < 0)
        {
            return false;
        }

        hashObjectHandle_ = hashHandle;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Update(const unsigned char* data, const unsigned int dataSize)
{
    try
    {
        if (hashObjectHandle_ == nullptr || (dataSize > 0 && data == nullptr))
        {
            return false;
        }

        if (dataSize == 0)
        {
            return true;
        }

        return BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(hashObjectHandle_),
                              const_cast<PUCHAR>(data), dataSize, 0) >= 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool CMicrosoftProvider::Final(unsigned char* hash, const unsigned int hashSize)
{
    try
    {
        if (hashObjectHandle_ == nullptr || hash == nullptr || hashSize < hashOutputSize_)
        {
            return false;
        }

        const NTSTATUS status = BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(hashObjectHandle_),
                                                  hash, hashOutputSize_, 0);

        BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hashObjectHandle_));
        hashObjectHandle_ = nullptr;

        return status >= 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#include "BCryptProvider.h"

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
    const unsigned int BCRYPT_PROVIDER_KEY_SIZE = 32;
    const unsigned int BCRYPT_PROVIDER_NONCE_SIZE = 12;
    const unsigned int BCRYPT_PROVIDER_TAG_SIZE = 16;
}

CBCryptProvider::~CBCryptProvider()
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
    }
    catch (...)
    {
    }
}
// -----------------------------------------------------------------------------

CBCryptProvider::CBCryptProvider()
    : algorithmHandle_(nullptr),
      keyHandle_(nullptr),
      keyObjectSize_(0)
{
}
// -----------------------------------------------------------------------------

bool CBCryptProvider::Initialize(void)
{
    try
    {
        BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
        if (BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0)
        {
            return false;
        }

        if (BCryptSetProperty(algorithmHandle,
                              BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                              static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)),
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

        algorithmHandle_ = algorithmHandle;
        keyObjectSize_ = keyObjectSize;
        keyObject_.resize(keyObjectSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

unsigned int CBCryptProvider::GetKeySize(void) const
{
    return BCRYPT_PROVIDER_KEY_SIZE;
}
// -----------------------------------------------------------------------------

unsigned int CBCryptProvider::GetNonceSize(void) const
{
    return BCRYPT_PROVIDER_NONCE_SIZE;
}
// -----------------------------------------------------------------------------

unsigned int CBCryptProvider::GetTagSize(void) const
{
    return BCRYPT_PROVIDER_TAG_SIZE;
}
// -----------------------------------------------------------------------------

bool CBCryptProvider::SetKey(const unsigned char* key, const unsigned int keySize)
{
    try
    {
        if (key == nullptr || keySize != BCRYPT_PROVIDER_KEY_SIZE || algorithmHandle_ == nullptr)
        {
            return false;
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

        if (keyHandle_ != nullptr)
        {
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(keyHandle_));
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

bool CBCryptProvider::Encrypt(const unsigned char* nonce, const unsigned int nonceSize,
                              const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                              unsigned char* outputBuffer,
                              unsigned char* tag, const unsigned int tagSize)
{
    try
    {
        if (nonce == nullptr || tag == nullptr || keyHandle_ == nullptr ||
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

bool CBCryptProvider::Decrypt(const unsigned char* nonce, const unsigned int nonceSize,
                              const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                              const unsigned char* tag, const unsigned int tagSize,
                              unsigned char* outputBuffer)
{
    try
    {
        if (nonce == nullptr || tag == nullptr || keyHandle_ == nullptr ||
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

bool CBCryptProvider::DerivePasswordKey(const char* password, const unsigned int passwordSize,
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

bool CBCryptProvider::GenerateRandomBytes(unsigned char* buffer, const unsigned int bufferSize)
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

} // namespace CryptoApiNS

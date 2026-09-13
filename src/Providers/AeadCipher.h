#ifndef CRYPTOAPI_PROVIDERS_AEAD_CIPHER_H
#define CRYPTOAPI_PROVIDERS_AEAD_CIPHER_H

namespace CryptoApiNS
{

class IAeadCipher
{
public:
    virtual ~IAeadCipher();
             IAeadCipher();

    virtual unsigned int GetKeySize(void) const = 0;
    virtual unsigned int GetNonceSize(void) const = 0;
    virtual unsigned int GetTagSize(void) const = 0;

    virtual bool SetKey(const unsigned char* key, const unsigned int keySize) = 0;

    virtual bool Encrypt( const unsigned char* nonce, const unsigned int nonceSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          unsigned char* outputBuffer,
                          unsigned char* tag, const unsigned int tagSize) = 0;

    virtual bool Decrypt( const unsigned char* nonce, const unsigned int nonceSize,
                          const unsigned char* inputBuffer, const unsigned int inputBufferSize,
                          const unsigned char* tag, const unsigned int tagSize,
                          unsigned char* outputBuffer) = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

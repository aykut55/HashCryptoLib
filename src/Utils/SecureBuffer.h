#ifndef AYCRYPTO_SECURE_BUFFER_H
#define AYCRYPTO_SECURE_BUFFER_H

namespace CryptoApiNS
{

// Owns a heap-allocated copy of secret byte data (e.g. a PFX password) and guarantees the bytes
// are wiped (SecureZeroMemory) before the memory is freed, unlike std::string/std::wstring whose
// internal buffer is left untouched on destruction/reallocation. Internal helper only -- never
// crosses the DLL ABI boundary (see CertificateManager.h's own "no struct/STL type crosses the
// ABI" convention), so callers must never expose this type in a public signature.
class CSecureBuffer
{
public:
    virtual ~CSecureBuffer();
             CSecureBuffer(const char* data, const int size);

    // Wipes and frees the held buffer immediately, rather than waiting for destruction.
    void Clear(void);

    // Null-terminated view of the held bytes -- safe to pass directly as a C-string (e.g. to
    // OpenSSL's PKCS12_parse/PKCS12_create) without producing a second, non-wiped copy.
    const char* Data(void) const;
    int Size(void) const;

protected:

private:
    CSecureBuffer(const CSecureBuffer&) = delete;
    CSecureBuffer& operator=(const CSecureBuffer&) = delete;

    unsigned char* buffer_;
    int size_;
};

} // namespace CryptoApiNS

#endif

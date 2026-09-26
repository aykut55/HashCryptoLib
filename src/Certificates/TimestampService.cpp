#include "TimestampService.h"
#include "Definitions/Definitions.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winhttp.h>
#ifdef NO_ERROR
#undef NO_ERROR
#endif

#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pkcs7.h"
#include "openssl/ts.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace CryptoApiNS
{

namespace
{

struct TsReqDeleter        { void operator()(TS_REQ* p)          const { if (p) TS_REQ_free(p); } };
struct TsRespDeleter       { void operator()(TS_RESP* p)         const { if (p) TS_RESP_free(p); } };
struct TsMsgImprintDeleter { void operator()(TS_MSG_IMPRINT* p)  const { if (p) TS_MSG_IMPRINT_free(p); } };
struct X509AlgorDeleter    { void operator()(X509_ALGOR* p)      const { if (p) X509_ALGOR_free(p); } };
struct BnDeleter           { void operator()(BIGNUM* p)          const { if (p) BN_free(p); } };
struct Asn1IntegerDeleter  { void operator()(ASN1_INTEGER* p)    const { if (p) ASN1_INTEGER_free(p); } };
struct X509Deleter         { void operator()(X509* p)            const { if (p) X509_free(p); } };
struct X509StoreDeleter    { void operator()(X509_STORE* p)      const { if (p) X509_STORE_free(p); } };

typedef std::unique_ptr<TS_REQ, TsReqDeleter> TsReqPtr;
typedef std::unique_ptr<TS_RESP, TsRespDeleter> TsRespPtr;
typedef std::unique_ptr<TS_MSG_IMPRINT, TsMsgImprintDeleter> TsMsgImprintPtr;
typedef std::unique_ptr<X509_ALGOR, X509AlgorDeleter> X509AlgorPtr;
typedef std::unique_ptr<BIGNUM, BnDeleter> BnPtr;
typedef std::unique_ptr<ASN1_INTEGER, Asn1IntegerDeleter> Asn1IntegerPtr;
typedef std::unique_ptr<X509, X509Deleter> X509Ptr;
typedef std::unique_ptr<X509_STORE, X509StoreDeleter> X509StorePtr;

int WriteBytesOut(const void* data, const std::size_t dataSize, const int outputCapacity, void* outputBuffer, int* outputSize)
{
    if (outputSize == nullptr)
    {
        return INVALID_ARGUMENT;
    }
    *outputSize = static_cast<int>(dataSize);
    if (outputBuffer == nullptr || outputCapacity < static_cast<int>(dataSize))
    {
        return BUFFER_TOO_SMALL;
    }
    if (dataSize > 0)
    {
        std::memcpy(outputBuffer, data, dataSize);
    }
    return NO_ERROR;
}
// -----------------------------------------------------------------------------

int WriteTextOut(const std::string& text, const int outputCapacity, char* outputBuffer, int* outputSize)
{
    return WriteBytesOut(text.data(), text.size(), outputCapacity, outputBuffer, outputSize);
}
// -----------------------------------------------------------------------------

const EVP_MD* TimestampDigestToEvpMd(const TimestampDigestAlgorithm digestAlgorithm)
{
    switch (digestAlgorithm)
    {
    case TIMESTAMP_DIGEST_SHA384: return EVP_sha384();
    case TIMESTAMP_DIGEST_SHA512: return EVP_sha512();
    default:                      return EVP_sha256();
    }
}
// -----------------------------------------------------------------------------

int TimestampDigestToNid(const TimestampDigestAlgorithm digestAlgorithm)
{
    switch (digestAlgorithm)
    {
    case TIMESTAMP_DIGEST_SHA384: return NID_sha384;
    case TIMESTAMP_DIGEST_SHA512: return NID_sha512;
    default:                      return NID_sha256;
    }
}
// -----------------------------------------------------------------------------

std::wstring Utf8ToWide(const char* utf8, const int utf8Size)
{
    if (utf8 == nullptr || utf8Size <= 0)
    {
        return std::wstring();
    }
    const int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8, utf8Size, nullptr, 0);
    if (wideLen <= 0)
    {
        return std::wstring();
    }
    std::wstring wide(static_cast<std::size_t>(wideLen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, utf8Size, &wide[0], wideLen);
    return wide;
}
// -----------------------------------------------------------------------------

std::string BytesToHexString(const unsigned char* data, const std::size_t size)
{
    static const char* hexDigits = "0123456789ABCDEF";
    std::string out;
    out.resize(size * 2);
    for (std::size_t i = 0; i < size; ++i)
    {
        out[i * 2]     = hexDigits[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexDigits[data[i] & 0xF];
    }
    return out;
}
// -----------------------------------------------------------------------------

std::string Asn1TimeToString(const ASN1_TIME* time)
{
    if (time == nullptr)
    {
        return std::string();
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr)
    {
        return std::string();
    }
    ASN1_TIME_print(bio, time);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    std::string result;
    if (len > 0 && data != nullptr)
    {
        result.assign(data, static_cast<std::size_t>(len));
    }
    BIO_free(bio);
    return result;
}
// -----------------------------------------------------------------------------

} // namespace

CTimestampService::~CTimestampService()
{
}
// -----------------------------------------------------------------------------

CTimestampService::CTimestampService()
{
}
// -----------------------------------------------------------------------------

int CTimestampService::CreateTimestampRequest( const unsigned char* digestBuffer, const int digestBufferSize,
                                               const TimestampDigestAlgorithm digestAlgorithm,
                                               const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (digestBuffer == nullptr || digestBufferSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        TsReqPtr req(TS_REQ_new());
        if (!req)
        {
            return UNEXPECTED_ERROR;
        }
        TS_REQ_set_version(req.get(), 1);

        {
            X509AlgorPtr algo(X509_ALGOR_new());
            if (!algo || X509_ALGOR_set_md(algo.get(), TimestampDigestToEvpMd(digestAlgorithm)) != 1)
            {
                return UNEXPECTED_ERROR;
            }
            TsMsgImprintPtr msgImprint(TS_MSG_IMPRINT_new());
            if (!msgImprint)
            {
                return UNEXPECTED_ERROR;
            }
            if (TS_MSG_IMPRINT_set_algo(msgImprint.get(), algo.get()) != 1)
            {
                return UNEXPECTED_ERROR;
            }
            if (TS_MSG_IMPRINT_set_msg(msgImprint.get(), const_cast<unsigned char*>(digestBuffer), digestBufferSize) != 1)
            {
                return UNEXPECTED_ERROR;
            }
            if (TS_REQ_set_msg_imprint(req.get(), msgImprint.get()) != 1)
            {
                return UNEXPECTED_ERROR;
            }
        }

        TS_REQ_set_cert_req(req.get(), 1);

        {
            BnPtr nonceBn(BN_new());
            Asn1IntegerPtr nonce(ASN1_INTEGER_new());
            if (!nonceBn || !nonce || BN_rand(nonceBn.get(), 64, 0, 0) != 1 ||
                BN_to_ASN1_INTEGER(nonceBn.get(), nonce.get()) == nullptr)
            {
                return UNEXPECTED_ERROR;
            }
            TS_REQ_set_nonce(req.get(), nonce.get());
        }

        unsigned char* derPtr = nullptr;
        const int derLen = i2d_TS_REQ(req.get(), &derPtr);
        if (derLen <= 0 || derPtr == nullptr)
        {
            return UNEXPECTED_ERROR;
        }
        std::vector<unsigned char> der(derPtr, derPtr + derLen);
        OPENSSL_free(derPtr);

        return WriteBytesOut(der.data(), der.size(), outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CTimestampService::RequestTimestampFromTsa( const char* tsaUrl, const int tsaUrlSize,
                                                const unsigned char* requestDerBuffer, const int requestDerBufferSize,
                                                const int timeoutMilliseconds,
                                                const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (tsaUrl == nullptr || tsaUrlSize <= 0 || requestDerBuffer == nullptr || requestDerBufferSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const std::wstring wideUrl = Utf8ToWide(tsaUrl, tsaUrlSize);

        wchar_t hostName[256];
        hostName[0] = L'\0';
        wchar_t urlPath[2048];
        urlPath[0] = L'\0';

        URL_COMPONENTS urlComponents;
        ZeroMemory(&urlComponents, sizeof(urlComponents));
        urlComponents.dwStructSize = sizeof(urlComponents);
        urlComponents.lpszHostName = hostName;
        urlComponents.dwHostNameLength = 256;
        urlComponents.lpszUrlPath = urlPath;
        urlComponents.dwUrlPathLength = 2048;

        if (!WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &urlComponents))
        {
            return FILE_IO_ERROR;
        }

        const bool isHttps = (urlComponents.nScheme == INTERNET_SCHEME_HTTPS);

        HINTERNET hSession = WinHttpOpen( L"CryptoAPI-TimestampService/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession == nullptr)
        {
            return FILE_IO_ERROR;
        }

        WinHttpSetTimeouts(hSession, timeoutMilliseconds, timeoutMilliseconds, timeoutMilliseconds, timeoutMilliseconds);

        HINTERNET hConnect = WinHttpConnect(hSession, urlComponents.lpszHostName, urlComponents.nPort, 0);
        if (hConnect == nullptr)
        {
            WinHttpCloseHandle(hSession);
            return FILE_IO_ERROR;
        }

        HINTERNET hRequest = WinHttpOpenRequest( hConnect, L"POST", urlComponents.lpszUrlPath, nullptr, WINHTTP_NO_REFERER,
                                                 WINHTTP_DEFAULT_ACCEPT_TYPES, isHttps ? WINHTTP_FLAG_SECURE : 0);
        if (hRequest == nullptr)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return FILE_IO_ERROR;
        }

        const wchar_t* headers = L"Content-Type: application/timestamp-query";
        BOOL sendOk = WinHttpSendRequest( hRequest, headers, static_cast<DWORD>(-1),
                                         const_cast<void*>(static_cast<const void*>(requestDerBuffer)), static_cast<DWORD>(requestDerBufferSize),
                                         static_cast<DWORD>(requestDerBufferSize), 0);
        if (sendOk)
        {
            sendOk = WinHttpReceiveResponse(hRequest, nullptr);
        }

        std::vector<unsigned char> responseBytes;
        if (sendOk)
        {
            DWORD available = 0;
            while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0)
            {
                std::vector<unsigned char> chunk(available);
                DWORD readBytes = 0;
                if (!WinHttpReadData(hRequest, chunk.data(), available, &readBytes))
                {
                    break;
                }
                responseBytes.insert(responseBytes.end(), chunk.begin(), chunk.begin() + readBytes);
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (!sendOk || responseBytes.empty())
        {
            return FILE_IO_ERROR;
        }

        return WriteBytesOut(responseBytes.data(), responseBytes.size(), outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CTimestampService::VerifyTimestampResponse( const unsigned char* responseDerBuffer, const int responseDerBufferSize,
                                                 const unsigned char* originalDigestBuffer, const int originalDigestBufferSize,
                                                 const TimestampDigestAlgorithm digestAlgorithm,
                                                 const unsigned char* tsaTrustedCertDerBuffer, const int tsaTrustedCertDerBufferSize,
                                                 int* verificationResult)
{
    try
    {
        if (responseDerBuffer == nullptr || responseDerBufferSize <= 0 ||
            originalDigestBuffer == nullptr || originalDigestBufferSize <= 0 || verificationResult == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const unsigned char* p = responseDerBuffer;
        TsRespPtr resp(d2i_TS_RESP(nullptr, &p, responseDerBufferSize));
        if (!resp)
        {
            *verificationResult = TIMESTAMP_VERIFICATION_TECHNICAL_ERROR;
            return NO_ERROR;
        }

        TS_TST_INFO* tstInfo = TS_RESP_get_tst_info(resp.get());
        if (tstInfo == nullptr)
        {
            *verificationResult = TIMESTAMP_VERIFICATION_TECHNICAL_ERROR;
            return NO_ERROR;
        }

        TS_MSG_IMPRINT* imprint = TS_TST_INFO_get_msg_imprint(tstInfo);
        ASN1_OCTET_STRING* hashedMsg = (imprint != nullptr) ? TS_MSG_IMPRINT_get_msg(imprint) : nullptr;
        X509_ALGOR* imprintAlgo = (imprint != nullptr) ? TS_MSG_IMPRINT_get_algo(imprint) : nullptr;

        bool digestMatches = false;
        if (hashedMsg != nullptr)
        {
            const unsigned char* impData = ASN1_STRING_get0_data(hashedMsg);
            const int impLen = ASN1_STRING_length(hashedMsg);
            digestMatches = (impLen == originalDigestBufferSize) &&
                            (std::memcmp(impData, originalDigestBuffer, static_cast<std::size_t>(impLen)) == 0);
        }
        bool algoMatches = false;
        if (imprintAlgo != nullptr)
        {
            // X509_ALGOR_get0's 2nd out-param (pptype) is the ASN.1 type TAG of the algorithm's
            // parameters field (e.g. V_ASN1_NULL) -- NOT the algorithm identifier itself. The
            // actual hash algorithm OID comes back through the 1st out-param (paobj).
            const ASN1_OBJECT* algoObj = nullptr;
            X509_ALGOR_get0(&algoObj, nullptr, nullptr, imprintAlgo);
            algoMatches = (algoObj != nullptr) && (OBJ_obj2nid(algoObj) == TimestampDigestToNid(digestAlgorithm));
        }

        if (!digestMatches || !algoMatches)
        {
            *verificationResult = TIMESTAMP_VERIFICATION_TAMPERED_DIGEST;
            return NO_ERROR;
        }

        PKCS7* token = TS_RESP_get_token(resp.get());
        if (token == nullptr)
        {
            *verificationResult = TIMESTAMP_VERIFICATION_TECHNICAL_ERROR;
            return NO_ERROR;
        }

        const int cryptoOk = PKCS7_verify(token, nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY);
        if (cryptoOk != 1)
        {
            *verificationResult = TIMESTAMP_VERIFICATION_TAMPERED_DIGEST;
            return NO_ERROR;
        }

        if (tsaTrustedCertDerBuffer == nullptr || tsaTrustedCertDerBufferSize <= 0)
        {
            *verificationResult = TIMESTAMP_VERIFICATION_VALID;
            return NO_ERROR;
        }

        const unsigned char* rootP = tsaTrustedCertDerBuffer;
        X509Ptr trustedRoot(d2i_X509(nullptr, &rootP, tsaTrustedCertDerBufferSize));
        if (!trustedRoot)
        {
            return INVALID_ARGUMENT;
        }
        X509StorePtr store(X509_STORE_new());
        if (!store || X509_STORE_add_cert(store.get(), trustedRoot.get()) != 1)
        {
            return UNEXPECTED_ERROR;
        }

        const int trustOk = PKCS7_verify(token, nullptr, store.get(), nullptr, nullptr, 0);
        *verificationResult = (trustOk == 1) ? TIMESTAMP_VERIFICATION_VALID : TIMESTAMP_VERIFICATION_UNTRUSTED_TSA;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CTimestampService::GetTimestampInfoText( const unsigned char* responseDerBuffer, const int responseDerBufferSize,
                                             const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const
{
    try
    {
        if (responseDerBuffer == nullptr || responseDerBufferSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const unsigned char* p = responseDerBuffer;
        TsRespPtr resp(d2i_TS_RESP(nullptr, &p, responseDerBufferSize));
        if (!resp)
        {
            return INVALID_DATA;
        }

        TS_TST_INFO* tstInfo = TS_RESP_get_tst_info(resp.get());
        if (tstInfo == nullptr)
        {
            return INVALID_DATA;
        }

        std::string text;

        text += "GenTime: " + Asn1TimeToString(TS_TST_INFO_get_time(tstInfo)) + "\n";

        {
            const ASN1_INTEGER* serial = TS_TST_INFO_get_serial(tstInfo);
            if (serial != nullptr)
            {
                BnPtr serialBn(ASN1_INTEGER_to_BN(serial, nullptr));
                if (serialBn)
                {
                    char* serialHex = BN_bn2hex(serialBn.get());
                    if (serialHex != nullptr)
                    {
                        text += "SerialHex: " + std::string(serialHex) + "\n";
                        OPENSSL_free(serialHex);
                    }
                }
            }
        }

        {
            GENERAL_NAME* tsaName = TS_TST_INFO_get_tsa(tstInfo);
            if (tsaName != nullptr && tsaName->type == GEN_DIRNAME)
            {
                BIO* bio = BIO_new(BIO_s_mem());
                if (bio != nullptr)
                {
                    X509_NAME_print_ex(bio, tsaName->d.directoryName, 0, XN_FLAG_RFC2253);
                    char* data = nullptr;
                    const long len = BIO_get_mem_data(bio, &data);
                    if (len > 0 && data != nullptr)
                    {
                        text += "TsaName: " + std::string(data, static_cast<std::size_t>(len)) + "\n";
                    }
                    BIO_free(bio);
                }
            }
        }

        return WriteTextOut(text, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

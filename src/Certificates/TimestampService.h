#ifndef AYCRYPTO_TIMESTAMP_SERVICE_H
#define AYCRYPTO_TIMESTAMP_SERVICE_H

#include "Definitions/Definitions.h"
#include "Interfaces/ITimestampService.h"

#include <memory>

// Same DLL export/import boundary reasoning as Pgp/PgpEngine.h's own identical block.
#if defined(CRYPTOAPI_DLL_EXPORTS)
#define CRYPTOAPI_API __declspec(dllexport)
#elif defined(CRYPTOAPI_DLL_IMPORTS)
#define CRYPTOAPI_API __declspec(dllimport)
#else
#define CRYPTOAPI_API
#endif

namespace CryptoApiNS
{

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4251)
#pragma warning(disable: 4275)
#endif

// RFC 3161 timestamping -- closes Plan.md 29.4's real gap (§29.4 item 6). OpenSSL ts.h for the
// TS_REQ/TS_RESP ASN.1 structures; WinHTTP internally (an implementation detail of
// RequestTimestampFromTsa only, not a general network API -- see that method's own doc comment)
// for the actual `application/timestamp-query` HTTP POST to a real TSA. Stateless, same reasoning
// as CCmsService.
class CRYPTOAPI_API CTimestampService : public ITimestampService
{
public:
    virtual ~CTimestampService();
             CTimestampService();

    int CreateTimestampRequest( const unsigned char* digestBuffer, const int digestBufferSize,
                               const TimestampDigestAlgorithm digestAlgorithm,
                               const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // WinHTTP performs the actual network round trip here -- this is the one method in this SDK
    // (outside the still-unimplemented Plan.md §26/27 TLS/SSH modules) that touches the network,
    // scoped narrowly to exactly the RFC 3161 TSA request/response exchange, same spirit as
    // CPgpEngineWrapper shelling out to gpg.exe for an external capability rather than
    // reimplementing it.
    int RequestTimestampFromTsa( const char* tsaUrl, const int tsaUrlSize,
                                const unsigned char* requestDerBuffer, const int requestDerBufferSize,
                                const int timeoutMilliseconds,
                                const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) override;

    // Two-pass verification, same shape as CCmsService::VerifyDetached: pass 1 checks the
    // embedded message-imprint digest matches originalDigestBuffer AND the token's own signature
    // is cryptographically valid (PKCS7_NOVERIFY -- no certificate trust check yet); failing
    // either always means TIMESTAMP_VERIFICATION_TAMPERED_DIGEST. Only if pass 1 succeeds AND a
    // tsaTrustedCertDerBuffer was supplied does pass 2 check the embedded TSA certificate chains
    // to it; failing only pass 2 means TIMESTAMP_VERIFICATION_UNTRUSTED_TSA.
    int VerifyTimestampResponse( const unsigned char* responseDerBuffer, const int responseDerBufferSize,
                                const unsigned char* originalDigestBuffer, const int originalDigestBufferSize,
                                const TimestampDigestAlgorithm digestAlgorithm,
                                const unsigned char* tsaTrustedCertDerBuffer, const int tsaTrustedCertDerBufferSize,
                                int* verificationResult) override;

    int GetTimestampInfoText( const unsigned char* responseDerBuffer, const int responseDerBufferSize,
                             const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const override;

protected:

private:

};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace CryptoApiNS

#endif

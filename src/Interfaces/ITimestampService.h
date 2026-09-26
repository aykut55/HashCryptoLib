#ifndef CRYPTOAPI_ITIMESTAMP_SERVICE_H
#define CRYPTOAPI_ITIMESTAMP_SERVICE_H

#include "Definitions/Definitions.h"

namespace CryptoApiNS
{

// Digest algorithm the original digest being timestamped was computed with -- deliberately
// independent from ICertificateManager.h's CertificateDigestAlgorithm and ICmsService.h's
// CmsDigestAlgorithm, same reasoning as those two headers' own comments.
enum TimestampDigestAlgorithm
{
    TIMESTAMP_DIGEST_SHA256 = 0,
    TIMESTAMP_DIGEST_SHA384 = 1,
    TIMESTAMP_DIGEST_SHA512 = 2
};

// VerifyTimestampResponse's *verificationResult out-parameter -- same shape as
// ICmsService.h's CmsVerificationResult, for the same reason (Plan.md 10's Valid/Invalid/
// Indeterminate + separate-technical-error convention). TIMESTAMP_VERIFICATION_UNTRUSTED_TSA is
// only reachable when VerifyTimestampResponse was given a TSA trust certificate (see that
// method's own doc comment) -- same optionality as CmsVerificationResult's untrusted-signer case.
enum TimestampVerificationResult
{
    TIMESTAMP_VERIFICATION_VALID            = 0,
    TIMESTAMP_VERIFICATION_TAMPERED_DIGEST  = 1,
    TIMESTAMP_VERIFICATION_UNTRUSTED_TSA    = 2,
    TIMESTAMP_VERIFICATION_TECHNICAL_ERROR  = 3
};

// Pure-virtual mirror of CTimestampService's instance methods (see Certificates/
// TimestampService.h for full documentation -- not repeated here to avoid drift between the two).
// Same DLL-boundary reasoning as ICertificateManager/ICmsService/IPgpEngine.
class ITimestampService
{
public:
    virtual ~ITimestampService();
             ITimestampService();

    // Builds an RFC 3161 TimeStampReq (TS_REQ) over a digest the caller already computed
    // (digestBuffer/digestAlgorithm identify it; this method never hashes anything itself).
    // certReq is always set true (asks the TSA to embed its own signing certificate in the
    // response, needed by VerifyTimestampResponse's optional trust check below).
    virtual int CreateTimestampRequest( const unsigned char* digestBuffer, const int digestBufferSize,
                                        const TimestampDigestAlgorithm digestAlgorithm,
                                        const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    // Performs the actual `application/timestamp-query` HTTP POST to tsaUrl (WinHTTP internally --
    // an implementation detail of this method, not a general network API; see Certificates/
    // TimestampService.h for why), sending requestDerBuffer as the body and returning the TSA's
    // TimeStampResp (TS_RESP) in outputBuffer. timeoutMilliseconds bounds connect+send+receive
    // together. FILE_IO_ERROR is reused for network/transport failures (connect refused, DNS
    // failure, timeout) since ErrorCode (Definitions.h) has no dedicated network category.
    virtual int RequestTimestampFromTsa( const char* tsaUrl, const int tsaUrlSize,
                                        const unsigned char* requestDerBuffer, const int requestDerBufferSize,
                                        const int timeoutMilliseconds,
                                        const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize) = 0;

    // Verifies responseDerBuffer (as returned by RequestTimestampFromTsa) actually timestamps
    // originalDigestBuffer. When tsaTrustedCertDerBufferSize is 0 (tsaTrustedCertDerBuffer may be
    // nullptr), only the embedded messageImprint match and the response's own signature are
    // checked -- *verificationResult is then never TIMESTAMP_VERIFICATION_UNTRUSTED_TSA.
    virtual int VerifyTimestampResponse( const unsigned char* responseDerBuffer, const int responseDerBufferSize,
                                        const unsigned char* originalDigestBuffer, const int originalDigestBufferSize,
                                        const TimestampDigestAlgorithm digestAlgorithm,
                                        const unsigned char* tsaTrustedCertDerBuffer, const int tsaTrustedCertDerBufferSize,
                                        int* verificationResult) = 0;

    // Reads genTime/serial number/TSA name out of responseDerBuffer as a human-readable text
    // block, WITHOUT verifying anything -- same "inspect without checking" philosophy as
    // ICmsService::ExtractSignerCertificate.
    virtual int GetTimestampInfoText( const unsigned char* responseDerBuffer, const int responseDerBufferSize,
                                     const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize) const = 0;

protected:

private:

};

} // namespace CryptoApiNS

#endif

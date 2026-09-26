#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_TIMESTAMP_SERVICE_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_TIMESTAMP_SERVICE_H

#include "Definitions/Definitions.h"
#include "Certificates/TimestampService.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// Script-facing convenience facade over CTimestampService -- same treatment as CScriptPgpEngine/
// CScriptCertificateManager/CScriptCmsService (see their own header comments): digestAlgorithm is
// a plain int here (0=SHA256, 1=SHA384, 2=SHA512, matching TimestampDigestAlgorithm).
// verificationResult is returned as int (0=Valid, 1=TamperedDigest, 2=UntrustedTsa,
// 3=TechnicalError, matching TimestampVerificationResult).
class CScriptTimestampService
{
public:
    virtual ~CScriptTimestampService();
             CScriptTimestampService();

    std::vector<unsigned char> CreateTimestampRequest(const std::vector<unsigned char>& digest, const int digestAlgorithm);

    // Performs the real network round trip to tsaUrl -- see CTimestampService::RequestTimestampFromTsa's
    // own doc comment.
    std::vector<unsigned char> RequestTimestampFromTsa( const std::string& tsaUrl, const std::vector<unsigned char>& requestDer,
                                                        const int timeoutMilliseconds);

    // tsaTrustedCertDer may be an empty vector to request the crypto-only check.
    int VerifyTimestampResponse( const std::vector<unsigned char>& responseDer, const std::vector<unsigned char>& originalDigest,
                                const int digestAlgorithm, const std::vector<unsigned char>& tsaTrustedCertDer);

    std::string GetTimestampInfoText(const std::vector<unsigned char>& responseDer) const;

protected:

private:

    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;

    CTimestampService engine_;

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_CMS_SERVICE_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_CMS_SERVICE_H

#include "Definitions/Definitions.h"
#include "Certificates/CmsService.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// Script-facing convenience facade over CCmsService -- same treatment as CScriptPgpEngine/
// CScriptCertificateManager (see their own header comments): digestAlgorithm is a plain int here
// (0=SHA256, 1=SHA384, 2=SHA512, matching CmsDigestAlgorithm) rather than a registered script enum
// type, same reasoning as CScriptCertificateManager's own header comment. verificationResult is
// returned as int (0=Valid, 1=TamperedData, 2=UntrustedSigner, 3=TechnicalError, matching
// CmsVerificationResult) rather than an out-parameter, since every method here returns exactly one
// value.
class CScriptCmsService
{
public:
    virtual ~CScriptCmsService();
             CScriptCmsService();

    std::vector<unsigned char> SignDetached( const std::vector<unsigned char>& data, const std::vector<unsigned char>& signerCertDer,
                                             const std::string& signerPrivateKeyPem, const int digestAlgorithm);

    // trustedRootCertDer may be an empty vector to request the crypto-only check (see
    // CCmsService::VerifyDetached's own doc comment for what that means).
    int VerifyDetached( const std::vector<unsigned char>& data, const std::vector<unsigned char>& cmsDer,
                       const std::vector<unsigned char>& trustedRootCertDer);

    std::vector<unsigned char> ExtractSignerCertificate(const std::vector<unsigned char>& cmsDer) const;

protected:

private:

    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;

    CCmsService engine_;

};

} // namespace CryptoApiNS

#endif

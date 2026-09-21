#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_CRYPTO_API_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_CRYPTO_API_H

#include "CryptoApi.h"
#include "Definitions/Definitions.h"
#include "Providers/ProviderTypes.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// Script-facing convenience facade over CCryptoApi: every raw C-ABI method (raw pointer + capacity
// + out-size, ErrorCode return) gets a std::string/std::vector<unsigned char> counterpart here that
// does the two-call capacity-query dance internally and throws CScriptException instead of
// returning an ErrorCode -- see ScriptException.h for why this is a deliberate, scoped exception to
// Rules.md's usual "exception never crosses a boundary" rule. GetShared()/ResetShared()/Instance()
// are deliberately NOT mirrored here: every script-created engine owns its own CScriptCryptoApi
// wrapping a plain (uncached, unshared) CCryptoApi instance, matching this class's constructor set
// (which mirrors CCryptoApi's plain constructors only). ProgressCallback is not exposed to scripts
// yet (v1) -- every wrapped call below passes nullptr/nullptr for it; script-visible progress
// reporting is a documented future addition, not implemented here.
class CScriptCryptoApi
{
public:
    virtual ~CScriptCryptoApi();
             CScriptCryptoApi();
             CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const HashAlgorithm hashAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const AsymmetricAlgorithm asymmetricAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const LegacySymmetricAlgorithm legacyAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const SignatureAlgorithm signatureAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const KeyAgreementAlgorithm keyAgreementAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm);
             CScriptCryptoApi(const ProviderKind providerKind, const AeadAlgorithm aeadAlgorithm, const AsymmetricAlgorithm asymmetricAlgorithm, const LegacySymmetricAlgorithm legacyAlgorithm, const HashAlgorithm hashAlgorithm, const SignatureAlgorithm signatureAlgorithm, const KeyAgreementAlgorithm keyAgreementAlgorithm);

    std::string GetVersion(void) const;

    std::vector<unsigned char> EncryptBuffer(const std::string& password, const std::vector<unsigned char>& input);
    std::vector<unsigned char> DecryptBuffer(const std::string& password, const std::vector<unsigned char>& input);
    std::vector<unsigned char> EncryptBytes(const std::string& password, const std::vector<unsigned char>& input);
    std::vector<unsigned char> DecryptBytes(const std::string& password, const std::vector<unsigned char>& input);
    std::vector<unsigned char> EncryptString(const std::string& password, const std::string& input);
    std::string DecryptString(const std::string& password, const std::vector<unsigned char>& input);
    void EncryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath);
    void DecryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath);

    void GenerateAsymmetricKeyPair(void);
    int GetMaxAsymmetricPlaintextSize(void) const;
    int GetAsymmetricCiphertextSize(void) const;
    std::vector<unsigned char> EncryptWithPublicKey(const std::vector<unsigned char>& input);
    std::vector<unsigned char> DecryptWithPrivateKey(const std::vector<unsigned char>& input);

    std::vector<unsigned char> EncryptLegacyBuffer(const std::string& password, const std::vector<unsigned char>& input);
    std::vector<unsigned char> DecryptLegacyBuffer(const std::string& password, const std::vector<unsigned char>& input);

    int GetHashSize(void) const;
    std::vector<unsigned char> ComputeHashBuffer(const std::vector<unsigned char>& input);
    std::vector<unsigned char> ComputeHashBytes(const std::vector<unsigned char>& input);
    std::vector<unsigned char> ComputeHashString(const std::string& input);
    std::vector<unsigned char> ComputeHashFile(const std::string& inputFilePath);

    void GenerateSignatureKeyPair(void);
    int GetSignatureSize(void) const;
    std::vector<unsigned char> SignBuffer(const std::vector<unsigned char>& input);
    bool VerifyBuffer(const std::vector<unsigned char>& input, const std::vector<unsigned char>& signature);

    void GenerateKeyAgreementKeyPair(void);
    int GetKeyAgreementPublicKeySize(void) const;
    int GetSharedSecretSize(void) const;
    std::vector<unsigned char> ExportKeyAgreementPublicKey(void);
    std::vector<unsigned char> DeriveSharedSecret(const std::vector<unsigned char>& peerPublicKey);

    std::vector<unsigned char> GenerateRandomBytes(const int outputSize);
    std::vector<unsigned char> GenerateRandomBytes(const RandomAlgorithm randomAlgorithm, const int outputSize);

protected:

private:

    // Generic two-call capacity-query dance shared by every CCryptoApi method that follows the
    // (capacity, unsigned char* buffer, int* actualSize) BUFFER_TOO_SMALL convention: fn performs
    // exactly one such call. Throws CScriptException on any ErrorCode other than NO_ERROR from the
    // second call (the first call's BUFFER_TOO_SMALL is expected and not itself an error).
    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;

    // Same as callBinaryOutput, for methods whose output buffer is char* (DecryptString) instead of
    // unsigned char*; the returned std::string is built from the exact reported length, never
    // assuming a null terminator (matching this buffer family's own "no auto terminator" contract).
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;

    // For methods with no output buffer at all (just an ErrorCode return) -- throws
    // CScriptException on any ErrorCode other than NO_ERROR.
    void callVoid(const char* methodName, const std::function<int(void)>& fn) const;

    CCryptoApi api_;

};

} // namespace CryptoApiNS

#endif

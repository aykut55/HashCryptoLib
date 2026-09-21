#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_PGP_ENGINE_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_PGP_ENGINE_H

#include "Definitions/Definitions.h"
#include "Pgp/PgpEngine.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// Script-facing convenience facade over CPgpEngine -- same treatment as CScriptCryptoApi (see its
// own header comment): every raw buffer method gets a std::string/std::vector<unsigned char>
// counterpart that does the buffer marshaling internally and throws CScriptException instead of
// returning an ErrorCode. ProgressCallback is not exposed to scripts yet (v1); every wrapped file
// method below passes nullptr/nullptr for it.
class CScriptPgpEngine
{
public:
    virtual ~CScriptPgpEngine();
             CScriptPgpEngine();
    explicit CScriptPgpEngine(const int rsaKeyBits);
    explicit CScriptPgpEngine(const PgpKeyAlgorithm keyAlgorithm);

    PgpKeyAlgorithm GetKeyAlgorithm(void) const;

    void GenerateKeyPair(const std::string& userId, const std::string& password);
    void GenerateKeyPair(const std::string& userId, const std::string& password, const unsigned int expirationSeconds);
    unsigned int GetKeyExpirationSeconds(void) const;
    std::string ExportPublicKeyArmored(void);
    std::string ExportSecretKeyArmored(void);
    std::string GetKeyId(void) const;
    std::string RevokeKeyArmored(const std::string& password, const unsigned char reasonCode, const std::string& reasonText);

    void ImportPeerPublicKey(const std::vector<unsigned char>& keyBlock);

    // Convenience overload: keyBlockArmored is handed straight through as raw bytes -- ImportPeerPublicKey
    // auto-detects ASCII-armored vs. binary from the leading bytes either way (see PgpEngine.h), so this
    // just saves a script author from manually building a byte array out of an armored string (e.g. one
    // returned by another engine's own ExportPublicKeyArmored()).
    void ImportPeerPublicKey(const std::string& keyBlockArmored);

    std::string GetPeerKeyId(void) const;
    void ImportAdditionalRecipientPublicKey(const std::vector<unsigned char>& keyBlock);

    // Convenience overload -- same reasoning as ImportPeerPublicKey(const std::string&) above.
    void ImportAdditionalRecipientPublicKey(const std::string& keyBlockArmored);

    std::vector<unsigned char> EncryptBuffer(const std::vector<unsigned char>& input);
    std::string EncryptStringArmored(const std::string& input);
    std::vector<unsigned char> DecryptBuffer(const std::string& password, const std::vector<unsigned char>& input);
    std::vector<unsigned char> DecryptStringArmored(const std::string& password, const std::string& input);

    std::vector<unsigned char> SignBuffer(const std::string& password, const std::vector<unsigned char>& input);
    bool VerifyBuffer(const std::vector<unsigned char>& input, const std::vector<unsigned char>& signature);

    std::string ClearSignString(const std::string& password, const std::string& input);
    bool VerifyClearSignedString(const std::string& clearSignedString);

    void EncryptFile(const std::string& inputFilePath, const std::string& outputFilePath);
    void EncryptFileCompressed(const std::string& inputFilePath, const std::string& outputFilePath, const PgpFileCompressionAlgorithm compressionAlgorithm);
    void DecryptFile(const std::string& password, const std::string& inputFilePath, const std::string& outputFilePath);
    void SignFile(const std::string& password, const std::string& inputFilePath, const std::string& signatureFilePath);
    bool VerifyFile(const std::string& inputFilePath, const std::string& signatureFilePath);

    bool IsPublicKeyEncrypted(const std::vector<unsigned char>& input) const;
    bool IsPasswordEncrypted(const std::vector<unsigned char>& input) const;
    bool IsIntegrityProtected(const std::vector<unsigned char>& input) const;
    int GetCompression(const std::vector<unsigned char>& input) const;
    std::vector<std::string> ListEncryptionKeyIds(const std::vector<unsigned char>& input) const;
    std::vector<std::string> ListSigningKeyIds(const std::vector<unsigned char>& input) const;
    std::vector<std::string> ListSignatures(const std::vector<unsigned char>& input) const;

protected:

private:

    // Same two-call capacity-query dance as CScriptCryptoApi::callBinaryOutput/callTextOutput (see
    // that class for the full rationale) -- duplicated here as a private helper rather than shared
    // across facade classes, matching this repo's existing per-class private-helper convention
    // (e.g. CCryptoApi's own encryptBuffer/decryptBuffer/computeHash helpers).
    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;
    void callVoid(const char* methodName, const std::function<int(void)>& fn) const;

    // GetKeyId/GetPeerKeyId have no capacity-query out-parameter -- fn writes into a fixed-size
    // buffer of `capacity` bytes and the result is read back up to its embedded null terminator
    // (both methods' own doc explicitly includes the null terminator in their required capacity).
    std::string callFixedTextOutput(const char* methodName, const int capacity, const std::function<int(char*, int)>& fn) const;

    // ListEncryptionKeyIds/ListSigningKeyIds/ListSignatures all write fixed-stride,
    // null-terminated records back to back; this splits the fetched buffer into `recordCount`
    // strings of at most `recordSize` bytes each (see PgpInspectionRecordSize in PgpEngine.h).
    std::vector<std::string> callRecordList(const char* methodName, const int recordSize, const std::function<int(int, char*, int*, int*)>& fn) const;

    CPgpEngine engine_;

};

} // namespace CryptoApiNS

#endif

#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_PGP_ENGINE_WRAPPER_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_PGP_ENGINE_WRAPPER_H

#include "Definitions/Definitions.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"

#include <functional>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// Script-facing convenience facade over CPgpEngineWrapper -- same treatment as CScriptPgpEngine
// (see that class's own header comment); covers every extra capability CPgpEngineWrapper adds over
// CPgpEngine too (ECC keygen, keyring introspection/removal, symmetric-only encryption, real
// multi-recipient encryption). ProgressCallback is not exposed to scripts yet (v1); every wrapped
// file method below passes nullptr/nullptr for it.
class CScriptPgpEngineWrapper
{
public:
    virtual ~CScriptPgpEngineWrapper();
             CScriptPgpEngineWrapper();
    explicit CScriptPgpEngineWrapper(const int rsaKeyBits);

    bool IsGnuPgAvailable(void) const;

    void GenerateKeyPair(const std::string& userId, const std::string& password);
    void GenerateKeyPair(const std::string& userId, const std::string& password, const unsigned int expirationSeconds);
    void GenerateKeyPairEcc(const std::string& userId, const std::string& password);
    void GenerateKeyPairEcc(const std::string& userId, const std::string& password, const unsigned int expirationSeconds);
    unsigned int GetKeyExpirationSeconds(void) const;
    std::string ExportPublicKeyArmored(void);
    std::string ExportSecretKeyArmored(void);
    std::string GetKeyId(void) const;
    std::string RevokeKeyArmored(const std::string& password, const unsigned char reasonCode, const std::string& reasonText);

    void ImportPeerPublicKey(const std::vector<unsigned char>& keyBlock);

    // Convenience overload -- see CScriptPgpEngine::ImportPeerPublicKey(const std::string&) for why.
    void ImportPeerPublicKey(const std::string& keyBlockArmored);

    std::string GetPeerKeyId(void) const;
    int GetImportedPeerKeyCount(void) const;
    std::string GetImportedPeerKeyId(const int peerIndex) const;

    std::string GetKeyringListing(void) const;
    int GetKeyringKeyCount(void) const;
    std::string GetKeyringKeyId(const int keyIndex) const;
    void DeletePeerPublicKey(const std::string& keyId);
    void DeleteOwnIdentity(void);

    std::vector<unsigned char> EncryptBuffer(const std::vector<unsigned char>& input);
    std::vector<unsigned char> EncryptBuffer(const std::vector<unsigned char>& input, const PgpCompressionAlgorithm compressionAlgorithm);
    std::string EncryptStringArmored(const std::string& input);
    std::string EncryptStringArmored(const std::string& input, const PgpCompressionAlgorithm compressionAlgorithm);

    std::vector<unsigned char> EncryptBufferSymmetric(const std::string& passphrase, const std::vector<unsigned char>& input);
    std::string EncryptStringArmoredSymmetric(const std::string& passphrase, const std::string& input);

    std::vector<unsigned char> EncryptBufferMultiRecipient(const std::vector<unsigned char>& input, const std::vector<std::string>& recipientKeyIds);
    std::vector<unsigned char> EncryptBufferMultiRecipient(const std::vector<unsigned char>& input, const std::vector<std::string>& recipientKeyIds, const PgpCompressionAlgorithm compressionAlgorithm);
    std::string EncryptStringArmoredMultiRecipient(const std::string& input, const std::vector<std::string>& recipientKeyIds);
    std::string EncryptStringArmoredMultiRecipient(const std::string& input, const std::vector<std::string>& recipientKeyIds, const PgpCompressionAlgorithm compressionAlgorithm);

    std::vector<unsigned char> DecryptBuffer(const std::string& password, const std::vector<unsigned char>& input);
    std::vector<unsigned char> DecryptStringArmored(const std::string& password, const std::string& input);

    std::vector<unsigned char> SignBuffer(const std::string& password, const std::vector<unsigned char>& input);
    bool VerifyBuffer(const std::vector<unsigned char>& input, const std::vector<unsigned char>& signature);

    std::string ClearSignString(const std::string& password, const std::string& input);
    bool VerifyClearSignedString(const std::string& clearSignedString);

    void EncryptFile(const std::string& inputFilePath, const std::string& outputFilePath);
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

    // Same two-call capacity-query dance as CScriptPgpEngine's own private helpers (see that
    // class's header comment for why this is duplicated per-class rather than shared).
    std::vector<unsigned char> callBinaryOutput(const char* methodName, const std::function<int(int, unsigned char*, int*)>& fn) const;
    std::string callTextOutput(const char* methodName, const std::function<int(int, char*, int*)>& fn) const;
    void callVoid(const char* methodName, const std::function<int(void)>& fn) const;
    std::string callFixedTextOutput(const char* methodName, const int capacity, const std::function<int(char*, int)>& fn) const;
    std::vector<std::string> callRecordList(const char* methodName, const int recordSize, const std::function<int(int, char*, int*, int*)>& fn) const;

    CPgpEngineWrapper engineWrapper_;

};

} // namespace CryptoApiNS

#endif

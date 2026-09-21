#include "LuaScriptEngineSol.h"
#include "../ScriptException.h"
#include "../ScriptCryptoApi.h"
#include "../ScriptPgpEngine.h"
#include "../ScriptPgpEngineWrapper.h"

#include "Definitions/Definitions.h"
#include "Providers/ProviderTypes.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"

namespace CryptoApiNS
{

CLuaScriptEngineSol::~CLuaScriptEngineSol()
{
}
// -----------------------------------------------------------------------------

CLuaScriptEngineSol::CLuaScriptEngineSol() : luaState_()
{
    luaState_.open_libraries(sol::lib::base, sol::lib::string, sol::lib::math, sol::lib::table, sol::lib::coroutine);
    registerBindings();
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineSol::RunFile(const std::string& filePath)
{
    try
    {
        luaState_.script_file(filePath);
    }
    catch (const sol::error& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("RunFile: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineSol::RunString(const std::string& code)
{
    try
    {
        luaState_.script(code);
    }
    catch (const sol::error& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("RunString: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

bool CLuaScriptEngineSol::GetGlobalBool(const std::string& name) const
{
    try
    {
        return luaState_.get_or(name, false);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

int CLuaScriptEngineSol::GetGlobalInt(const std::string& name) const
{
    try
    {
        return luaState_.get_or(name, 0);
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::string CLuaScriptEngineSol::GetGlobalString(const std::string& name) const
{
    try
    {
        return luaState_.get_or(name, std::string());
    }
    catch (...)
    {
        return std::string();
    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineSol::registerBindings(void)
{
    // ErrorCode / CScriptException -- scripts see a raised Lua error whose message is
    // CScriptException::what(); the numeric ErrorCode table below lets a script compare a caught
    // error's own reported code (via pcall) against these named constants if it parses the message,
    // or simply recognize the family of errors this SDK can raise.
    // sol2 registers std::vector<unsigned char> as a userdata-backed container the first time it is
    // pushed as a return value (every ...Buffer()/...Bytes() method above does this) -- once
    // registered that way, sol2 no longer auto-converts a plain Lua table into that same type for a
    // function PARAMETER (only a real vector userdata is accepted; see std::vector's own stack::get
    // implementation). ToBytes gives scripts a supported way to build one from a Lua string (UTF-8
    // bytes) for the handful of methods that take raw binary input (EncryptWithPublicKey, SignBuffer,
    // etc.) without needing a manual string.byte loop.
    luaState_.set_function("ToBytes", [](const std::string& text)
    {
        return std::vector<unsigned char>(text.begin(), text.end());
    });

    luaState_.new_enum("ErrorCode",
        "NO_ERROR", NO_ERROR,
        "NOT_IMPLEMENTED", NOT_IMPLEMENTED,
        "UNEXPECTED_ERROR", UNEXPECTED_ERROR,
        "BUFFER_TOO_SMALL", BUFFER_TOO_SMALL,
        "INVALID_ARGUMENT", INVALID_ARGUMENT,
        "FILE_IO_ERROR", FILE_IO_ERROR,
        "INVALID_DATA", INVALID_DATA,
        "OPERATION_CANCELLED", OPERATION_CANCELLED);

    luaState_.new_enum("ProviderKind",
        "PROVIDER_MICROSOFT", PROVIDER_MICROSOFT,
        "PROVIDER_CRYPTOPP", PROVIDER_CRYPTOPP,
        "PROVIDER_BOTAN", PROVIDER_BOTAN,
        "PROVIDER_OPENSSL", PROVIDER_OPENSSL,
        "PROVIDER_LIBGCRYPT", PROVIDER_LIBGCRYPT);

    luaState_.new_enum("AeadAlgorithm",
        "AEAD_AES_128_GCM", AEAD_AES_128_GCM,
        "AEAD_AES_192_GCM", AEAD_AES_192_GCM,
        "AEAD_AES_256_GCM", AEAD_AES_256_GCM,
        "AEAD_AES_128_CCM", AEAD_AES_128_CCM,
        "AEAD_AES_192_CCM", AEAD_AES_192_CCM,
        "AEAD_AES_256_CCM", AEAD_AES_256_CCM,
        "AEAD_AES_128_EAX", AEAD_AES_128_EAX,
        "AEAD_AES_192_EAX", AEAD_AES_192_EAX,
        "AEAD_AES_256_EAX", AEAD_AES_256_EAX,
        "AEAD_AES_128_SIV", AEAD_AES_128_SIV,
        "AEAD_AES_256_SIV", AEAD_AES_256_SIV,
        "AEAD_AES_128_GCM_SIV", AEAD_AES_128_GCM_SIV,
        "AEAD_AES_256_GCM_SIV", AEAD_AES_256_GCM_SIV,
        "AEAD_CHACHA20_POLY1305", AEAD_CHACHA20_POLY1305,
        "AEAD_TWOFISH_GCM", AEAD_TWOFISH_GCM,
        "AEAD_SERPENT_GCM", AEAD_SERPENT_GCM,
        "AEAD_CAMELLIA_GCM", AEAD_CAMELLIA_GCM);

    luaState_.new_enum("LegacySymmetricAlgorithm",
        "LEGACY_AES_128_CBC", LEGACY_AES_128_CBC,
        "LEGACY_AES_192_CBC", LEGACY_AES_192_CBC,
        "LEGACY_AES_256_CBC", LEGACY_AES_256_CBC,
        "LEGACY_AES_128_CTR", LEGACY_AES_128_CTR,
        "LEGACY_AES_192_CTR", LEGACY_AES_192_CTR,
        "LEGACY_AES_256_CTR", LEGACY_AES_256_CTR,
        "LEGACY_AES_128_CFB", LEGACY_AES_128_CFB,
        "LEGACY_AES_192_CFB", LEGACY_AES_192_CFB,
        "LEGACY_AES_256_CFB", LEGACY_AES_256_CFB,
        "LEGACY_AES_128_OFB", LEGACY_AES_128_OFB,
        "LEGACY_AES_192_OFB", LEGACY_AES_192_OFB,
        "LEGACY_AES_256_OFB", LEGACY_AES_256_OFB,
        "LEGACY_AES_128_ECB", LEGACY_AES_128_ECB,
        "LEGACY_AES_192_ECB", LEGACY_AES_192_ECB,
        "LEGACY_AES_256_ECB", LEGACY_AES_256_ECB,
        "LEGACY_RC2_CBC", LEGACY_RC2_CBC,
        "LEGACY_RC2_ECB", LEGACY_RC2_ECB,
        "LEGACY_DES_CBC", LEGACY_DES_CBC,
        "LEGACY_DES_ECB", LEGACY_DES_ECB,
        "LEGACY_3DES_CBC", LEGACY_3DES_CBC,
        "LEGACY_3DES_ECB", LEGACY_3DES_ECB,
        "LEGACY_RC4", LEGACY_RC4);

    luaState_.new_enum("AsymmetricAlgorithm",
        "ASYMMETRIC_RSA_1024", ASYMMETRIC_RSA_1024,
        "ASYMMETRIC_RSA_2048", ASYMMETRIC_RSA_2048,
        "ASYMMETRIC_RSA_3072", ASYMMETRIC_RSA_3072,
        "ASYMMETRIC_RSA_4096", ASYMMETRIC_RSA_4096);

    luaState_.new_enum("HashAlgorithm",
        "HASH_MD5", HASH_MD5,
        "HASH_SHA1", HASH_SHA1,
        "HASH_SHA224", HASH_SHA224,
        "HASH_SHA256", HASH_SHA256,
        "HASH_SHA384", HASH_SHA384,
        "HASH_SHA512", HASH_SHA512,
        "HASH_SHA512_256", HASH_SHA512_256,
        "HASH_SHA3_224", HASH_SHA3_224,
        "HASH_SHA3_256", HASH_SHA3_256,
        "HASH_SHA3_384", HASH_SHA3_384,
        "HASH_SHA3_512", HASH_SHA3_512,
        "HASH_BLAKE2B", HASH_BLAKE2B,
        "HASH_BLAKE2S", HASH_BLAKE2S,
        "HASH_RIPEMD160", HASH_RIPEMD160);

    luaState_.new_enum("SignatureAlgorithm",
        "SIGNATURE_RSA_PSS_SHA256_2048", SIGNATURE_RSA_PSS_SHA256_2048,
        "SIGNATURE_RSA_PSS_SHA256_3072", SIGNATURE_RSA_PSS_SHA256_3072,
        "SIGNATURE_RSA_PSS_SHA256_4096", SIGNATURE_RSA_PSS_SHA256_4096,
        "SIGNATURE_ECDSA_P256_SHA256", SIGNATURE_ECDSA_P256_SHA256,
        "SIGNATURE_ED25519", SIGNATURE_ED25519,
        "SIGNATURE_ECDSA_P384_SHA384", SIGNATURE_ECDSA_P384_SHA384,
        "SIGNATURE_ECDSA_P521_SHA512", SIGNATURE_ECDSA_P521_SHA512,
        "SIGNATURE_DSA_SHA256_2048", SIGNATURE_DSA_SHA256_2048,
        "SIGNATURE_DSA_SHA256_3072", SIGNATURE_DSA_SHA256_3072);

    luaState_.new_enum("KeyAgreementAlgorithm",
        "KEYAGREEMENT_ECDH_P256", KEYAGREEMENT_ECDH_P256,
        "KEYAGREEMENT_X25519", KEYAGREEMENT_X25519);

    luaState_.new_enum("RandomAlgorithm",
        "RANDOM_SYSTEM", RANDOM_SYSTEM,
        "RANDOM_HASH_DRBG", RANDOM_HASH_DRBG,
        "RANDOM_HMAC_DRBG", RANDOM_HMAC_DRBG,
        "RANDOM_CTR_DRBG", RANDOM_CTR_DRBG);

    luaState_.new_enum("PgpKeyAlgorithm",
        "PGP_KEY_ALGORITHM_RSA", PGP_KEY_ALGORITHM_RSA,
        "PGP_KEY_ALGORITHM_ED25519_X25519", PGP_KEY_ALGORITHM_ED25519_X25519);

    // Deliberately two distinct Lua enum tables, never merged -- PgpFileCompressionAlgorithm
    // (CPgpEngine::EncryptFileCompressed) and PgpCompressionAlgorithm (CPgpEngineWrapper) share the
    // same namespace but have different values for the same names (see PgpEngine.h/
    // PgpEngineWrapper.h's own comments on this).
    luaState_.new_enum("PgpFileCompressionAlgorithm",
        "PGP_FILE_COMPRESSION_ALGORITHM_ZIP", PGP_FILE_COMPRESSION_ALGORITHM_ZIP,
        "PGP_FILE_COMPRESSION_ALGORITHM_ZLIB", PGP_FILE_COMPRESSION_ALGORITHM_ZLIB);

    luaState_.new_enum("PgpCompressionAlgorithm",
        "PGP_COMPRESSION_ALGORITHM_NONE", PGP_COMPRESSION_ALGORITHM_NONE,
        "PGP_COMPRESSION_ALGORITHM_ZIP", PGP_COMPRESSION_ALGORITHM_ZIP,
        "PGP_COMPRESSION_ALGORITHM_ZLIB", PGP_COMPRESSION_ALGORITHM_ZLIB,
        "PGP_COMPRESSION_ALGORITHM_BZIP2", PGP_COMPRESSION_ALGORITHM_BZIP2);

    luaState_.new_enum("PgpCompressionInspectionResult",
        "PGP_COMPRESSION_NOT_PRESENT", PGP_COMPRESSION_NOT_PRESENT,
        "PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION", PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION);

    luaState_.new_enum("PgpInspectionRecordSize",
        "PGP_INSPECTION_KEY_ID_RECORD_SIZE", PGP_INSPECTION_KEY_ID_RECORD_SIZE,
        "PGP_INSPECTION_SIGNATURE_RECORD_SIZE", PGP_INSPECTION_SIGNATURE_RECORD_SIZE);

    luaState_.new_usertype<CScriptCryptoApi>("CryptoApi",
        sol::constructors<
            CScriptCryptoApi(),
            CScriptCryptoApi(const ProviderKind, const AeadAlgorithm),
            CScriptCryptoApi(const ProviderKind, const HashAlgorithm),
            CScriptCryptoApi(const ProviderKind, const AsymmetricAlgorithm),
            CScriptCryptoApi(const ProviderKind, const LegacySymmetricAlgorithm),
            CScriptCryptoApi(const ProviderKind, const SignatureAlgorithm),
            CScriptCryptoApi(const ProviderKind, const KeyAgreementAlgorithm),
            CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm),
            CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm),
            CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm),
            CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm, const SignatureAlgorithm),
            CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm, const SignatureAlgorithm, const KeyAgreementAlgorithm)
        >(),
        "GetVersion", &CScriptCryptoApi::GetVersion,
        "EncryptBuffer", &CScriptCryptoApi::EncryptBuffer,
        "DecryptBuffer", &CScriptCryptoApi::DecryptBuffer,
        "EncryptBytes", &CScriptCryptoApi::EncryptBytes,
        "DecryptBytes", &CScriptCryptoApi::DecryptBytes,
        "EncryptString", &CScriptCryptoApi::EncryptString,
        "DecryptString", &CScriptCryptoApi::DecryptString,
        "EncryptFile", &CScriptCryptoApi::EncryptFile,
        "DecryptFile", &CScriptCryptoApi::DecryptFile,
        "GenerateAsymmetricKeyPair", &CScriptCryptoApi::GenerateAsymmetricKeyPair,
        "GetMaxAsymmetricPlaintextSize", &CScriptCryptoApi::GetMaxAsymmetricPlaintextSize,
        "GetAsymmetricCiphertextSize", &CScriptCryptoApi::GetAsymmetricCiphertextSize,
        "EncryptWithPublicKey", &CScriptCryptoApi::EncryptWithPublicKey,
        "DecryptWithPrivateKey", &CScriptCryptoApi::DecryptWithPrivateKey,
        "EncryptLegacyBuffer", &CScriptCryptoApi::EncryptLegacyBuffer,
        "DecryptLegacyBuffer", &CScriptCryptoApi::DecryptLegacyBuffer,
        "GetHashSize", &CScriptCryptoApi::GetHashSize,
        "ComputeHashBuffer", &CScriptCryptoApi::ComputeHashBuffer,
        "ComputeHashBytes", &CScriptCryptoApi::ComputeHashBytes,
        "ComputeHashString", &CScriptCryptoApi::ComputeHashString,
        "ComputeHashFile", &CScriptCryptoApi::ComputeHashFile,
        "GenerateSignatureKeyPair", &CScriptCryptoApi::GenerateSignatureKeyPair,
        "GetSignatureSize", &CScriptCryptoApi::GetSignatureSize,
        "SignBuffer", &CScriptCryptoApi::SignBuffer,
        "VerifyBuffer", &CScriptCryptoApi::VerifyBuffer,
        "GenerateKeyAgreementKeyPair", &CScriptCryptoApi::GenerateKeyAgreementKeyPair,
        "GetKeyAgreementPublicKeySize", &CScriptCryptoApi::GetKeyAgreementPublicKeySize,
        "GetSharedSecretSize", &CScriptCryptoApi::GetSharedSecretSize,
        "ExportKeyAgreementPublicKey", &CScriptCryptoApi::ExportKeyAgreementPublicKey,
        "DeriveSharedSecret", &CScriptCryptoApi::DeriveSharedSecret,
        "GenerateRandomBytes", sol::overload(
            static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const int)>(&CScriptCryptoApi::GenerateRandomBytes),
            static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const RandomAlgorithm, const int)>(&CScriptCryptoApi::GenerateRandomBytes))
    );

    luaState_.new_usertype<CScriptPgpEngine>("PgpEngine",
        sol::constructors<
            CScriptPgpEngine(),
            CScriptPgpEngine(const int),
            CScriptPgpEngine(const PgpKeyAlgorithm)
        >(),
        "GetKeyAlgorithm", &CScriptPgpEngine::GetKeyAlgorithm,
        "GenerateKeyPair", sol::overload(
            static_cast<void(CScriptPgpEngine::*)(const std::string&, const std::string&)>(&CScriptPgpEngine::GenerateKeyPair),
            static_cast<void(CScriptPgpEngine::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngine::GenerateKeyPair)),
        "GetKeyExpirationSeconds", &CScriptPgpEngine::GetKeyExpirationSeconds,
        "ExportPublicKeyArmored", &CScriptPgpEngine::ExportPublicKeyArmored,
        "ExportSecretKeyArmored", &CScriptPgpEngine::ExportSecretKeyArmored,
        "GetKeyId", &CScriptPgpEngine::GetKeyId,
        "RevokeKeyArmored", &CScriptPgpEngine::RevokeKeyArmored,
        "ImportPeerPublicKey", sol::overload(
            static_cast<void(CScriptPgpEngine::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngine::ImportPeerPublicKey),
            static_cast<void(CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportPeerPublicKey)),
        "GetPeerKeyId", &CScriptPgpEngine::GetPeerKeyId,
        "ImportAdditionalRecipientPublicKey", sol::overload(
            static_cast<void(CScriptPgpEngine::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngine::ImportAdditionalRecipientPublicKey),
            static_cast<void(CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportAdditionalRecipientPublicKey)),
        "EncryptBuffer", &CScriptPgpEngine::EncryptBuffer,
        "EncryptStringArmored", &CScriptPgpEngine::EncryptStringArmored,
        "DecryptBuffer", &CScriptPgpEngine::DecryptBuffer,
        "DecryptStringArmored", &CScriptPgpEngine::DecryptStringArmored,
        "SignBuffer", &CScriptPgpEngine::SignBuffer,
        "VerifyBuffer", &CScriptPgpEngine::VerifyBuffer,
        "ClearSignString", &CScriptPgpEngine::ClearSignString,
        "VerifyClearSignedString", &CScriptPgpEngine::VerifyClearSignedString,
        "EncryptFile", &CScriptPgpEngine::EncryptFile,
        "EncryptFileCompressed", &CScriptPgpEngine::EncryptFileCompressed,
        "DecryptFile", &CScriptPgpEngine::DecryptFile,
        "SignFile", &CScriptPgpEngine::SignFile,
        "VerifyFile", &CScriptPgpEngine::VerifyFile,
        "IsPublicKeyEncrypted", &CScriptPgpEngine::IsPublicKeyEncrypted,
        "IsPasswordEncrypted", &CScriptPgpEngine::IsPasswordEncrypted,
        "IsIntegrityProtected", &CScriptPgpEngine::IsIntegrityProtected,
        "GetCompression", &CScriptPgpEngine::GetCompression,
        "ListEncryptionKeyIds", &CScriptPgpEngine::ListEncryptionKeyIds,
        "ListSigningKeyIds", &CScriptPgpEngine::ListSigningKeyIds,
        "ListSignatures", &CScriptPgpEngine::ListSignatures
    );

    luaState_.new_usertype<CScriptPgpEngineWrapper>("PgpEngineWrapper",
        sol::constructors<
            CScriptPgpEngineWrapper(),
            CScriptPgpEngineWrapper(const int)
        >(),
        "IsGnuPgAvailable", &CScriptPgpEngineWrapper::IsGnuPgAvailable,
        "GenerateKeyPair", sol::overload(
            static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&)>(&CScriptPgpEngineWrapper::GenerateKeyPair),
            static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngineWrapper::GenerateKeyPair)),
        "GenerateKeyPairEcc", sol::overload(
            static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&)>(&CScriptPgpEngineWrapper::GenerateKeyPairEcc),
            static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngineWrapper::GenerateKeyPairEcc)),
        "GetKeyExpirationSeconds", &CScriptPgpEngineWrapper::GetKeyExpirationSeconds,
        "ExportPublicKeyArmored", &CScriptPgpEngineWrapper::ExportPublicKeyArmored,
        "ExportSecretKeyArmored", &CScriptPgpEngineWrapper::ExportSecretKeyArmored,
        "GetKeyId", &CScriptPgpEngineWrapper::GetKeyId,
        "RevokeKeyArmored", &CScriptPgpEngineWrapper::RevokeKeyArmored,
        "ImportPeerPublicKey", sol::overload(
            static_cast<void(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngineWrapper::ImportPeerPublicKey),
            static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&)>(&CScriptPgpEngineWrapper::ImportPeerPublicKey)),
        "GetPeerKeyId", &CScriptPgpEngineWrapper::GetPeerKeyId,
        "GetImportedPeerKeyCount", &CScriptPgpEngineWrapper::GetImportedPeerKeyCount,
        "GetImportedPeerKeyId", &CScriptPgpEngineWrapper::GetImportedPeerKeyId,
        "GetKeyringListing", &CScriptPgpEngineWrapper::GetKeyringListing,
        "GetKeyringKeyCount", &CScriptPgpEngineWrapper::GetKeyringKeyCount,
        "GetKeyringKeyId", &CScriptPgpEngineWrapper::GetKeyringKeyId,
        "DeletePeerPublicKey", &CScriptPgpEngineWrapper::DeletePeerPublicKey,
        "DeleteOwnIdentity", &CScriptPgpEngineWrapper::DeleteOwnIdentity,
        "EncryptBuffer", sol::overload(
            static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngineWrapper::EncryptBuffer),
            static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptBuffer)),
        "EncryptStringArmored", sol::overload(
            static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&)>(&CScriptPgpEngineWrapper::EncryptStringArmored),
            static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptStringArmored)),
        "EncryptBufferSymmetric", &CScriptPgpEngineWrapper::EncryptBufferSymmetric,
        "EncryptStringArmoredSymmetric", &CScriptPgpEngineWrapper::EncryptStringArmoredSymmetric,
        "EncryptBufferMultiRecipient", sol::overload(
            static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const std::vector<std::string>&)>(&CScriptPgpEngineWrapper::EncryptBufferMultiRecipient),
            static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const std::vector<std::string>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptBufferMultiRecipient)),
        "EncryptStringArmoredMultiRecipient", sol::overload(
            static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const std::vector<std::string>&)>(&CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient),
            static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const std::vector<std::string>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient)),
        "DecryptBuffer", &CScriptPgpEngineWrapper::DecryptBuffer,
        "DecryptStringArmored", &CScriptPgpEngineWrapper::DecryptStringArmored,
        "SignBuffer", &CScriptPgpEngineWrapper::SignBuffer,
        "VerifyBuffer", &CScriptPgpEngineWrapper::VerifyBuffer,
        "ClearSignString", &CScriptPgpEngineWrapper::ClearSignString,
        "VerifyClearSignedString", &CScriptPgpEngineWrapper::VerifyClearSignedString,
        "EncryptFile", &CScriptPgpEngineWrapper::EncryptFile,
        "DecryptFile", &CScriptPgpEngineWrapper::DecryptFile,
        "SignFile", &CScriptPgpEngineWrapper::SignFile,
        "VerifyFile", &CScriptPgpEngineWrapper::VerifyFile,
        "IsPublicKeyEncrypted", &CScriptPgpEngineWrapper::IsPublicKeyEncrypted,
        "IsPasswordEncrypted", &CScriptPgpEngineWrapper::IsPasswordEncrypted,
        "IsIntegrityProtected", &CScriptPgpEngineWrapper::IsIntegrityProtected,
        "GetCompression", &CScriptPgpEngineWrapper::GetCompression,
        "ListEncryptionKeyIds", &CScriptPgpEngineWrapper::ListEncryptionKeyIds,
        "ListSigningKeyIds", &CScriptPgpEngineWrapper::ListSigningKeyIds,
        "ListSignatures", &CScriptPgpEngineWrapper::ListSignatures
    );
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

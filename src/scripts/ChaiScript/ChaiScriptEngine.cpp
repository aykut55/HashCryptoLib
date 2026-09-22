// Definitions.h (ErrorCode's enum { NO_ERROR = 0, ... }) MUST be the first thing this translation
// unit parses. ChaiScriptEngine.h pulls in <chaiscript/chaiscript.hpp>, which transitively includes
// <Windows.h> (for its threading support); WinError.h's own "#define NO_ERROR 0L" then textually
// replaces the enum's first member wherever it appears afterward -- INCLUDING at the enum's own
// declaration site if Definitions.h is parsed only later, turning "enum ErrorCode { NO_ERROR = 0"
// into the syntactically invalid "enum ErrorCode { 0L = 0" and cascading into every other member
// being reported "undeclared". Parsing Definitions.h here, before chaiscript.hpp ever gets a chance
// to define that macro, avoids the whole problem.
#include "Definitions/Definitions.h"

#include "ChaiScriptEngine.h"

// ChaiScriptEngine.h's own <chaiscript/chaiscript.hpp> just pulled in <Windows.h> (for ChaiScript's
// threading support), which leaves two macros defined for the rest of this translation unit -- and
// critically, that includes every header below this point, not just this file's own later code:
//   - NO_ERROR (WinError.h, "#define NO_ERROR 0L") -- see the comment at the top of this file for
//     why parsing Definitions.h first (before ChaiScriptEngine.h) keeps the enum DECLARATION itself
//     safe; this second #undef protects every later bare "NO_ERROR" token (e.g. in
//     registerBindings() below) from silently becoming the literal 0L instead of the real
//     CryptoApiNS::ErrorCode enumerator. Same precedent as src/DllLoader/CryptoApiDllLoader.h.
//   - EncryptFile/DecryptFile (winbase.h, real Win32 APIs, macro-aliased to their *W Unicode
//     overload under this project's UNICODE charset) -- MUST be undone before the facade headers
//     below are parsed: CScriptCryptoApi/CScriptPgpEngine/CScriptPgpEngineWrapper each declare a
//     method literally named EncryptFile/DecryptFile, and the preprocessor does not care that
//     those are class member declarations -- it macro-substitutes the token everywhere, silently
//     renaming the declared members themselves to EncryptFileW/DecryptFileW if this isn't undone
//     first. Same precedent as CryptoApi.cpp's own #undef of both.
#ifdef NO_ERROR
#undef NO_ERROR
#endif
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif

#include "../ScriptException.h"
#include "../ScriptCryptoApiDll.h"
#include "../ScriptPgpEngineDll.h"
#include "../ScriptPgpEngineWrapperDll.h"

// DLL_RUNNER (defined by DllRunner.vcxproj's PreprocessorDefinitions) skips every include/
// registration below that would otherwise pull in CCryptoApi/CPgpEngine/CPgpEngineWrapper's own
// concrete implementation -- see ScriptCryptoApiDll.h's own header comment for why DllRunner must
// never link that. Same technique CLuaScriptEngineSol.cpp's own guard already uses.
#ifndef DLL_RUNNER
#include "../ScriptCryptoApi.h"
#include "../ScriptPgpEngine.h"
#include "../ScriptPgpEngineWrapper.h"

#include "Providers/ProviderTypes.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"
#endif

#include <chaiscript/dispatchkit/bootstrap_stl.hpp>

#include <vector>

namespace CryptoApiNS
{

CChaiScriptEngine::~CChaiScriptEngine()
{
}
// -----------------------------------------------------------------------------

CChaiScriptEngine::CChaiScriptEngine() : chai_()
{
    registerBindings();
}
// -----------------------------------------------------------------------------

void CChaiScriptEngine::RunFile(const std::string& filePath)
{
    try
    {
        chai_.eval_file(filePath);
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("RunFile: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

void CChaiScriptEngine::RunString(const std::string& code)
{
    try
    {
        chai_.eval(code);
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("RunString: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

bool CChaiScriptEngine::GetGlobalBool(const std::string& name)
{
    try
    {
        return chai_.eval<bool>(name);
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

int CChaiScriptEngine::GetGlobalInt(const std::string& name)
{
    try
    {
        return chai_.eval<int>(name);
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::string CChaiScriptEngine::GetGlobalString(const std::string& name)
{
    try
    {
        return chai_.eval<std::string>(name);
    }
    catch (...)
    {
        return std::string();
    }
}
// -----------------------------------------------------------------------------

void CChaiScriptEngine::registerBindings(void)
{
    // std::vector<unsigned char> is what every ...Buffer()/...Bytes() facade method takes/returns;
    // this gives scripts .size()/[]/.empty() on it (register once, under a script-visible type name
    // that scripts never need to spell out themselves -- only the methods it enables matter).
    chai_.add(chaiscript::bootstrap::standard_library::vector_type<std::vector<unsigned char>>("ByteVector"));

    // ChaiScript's Boxed_Value type-erasure is exact-type based (unlike its numeric operators,
    // which get automatic int/double/etc. conversions via Boxed_Number) -- a std::string's per-
    // character iteration boxes plain `char`, which does not implicitly convert to the
    // `unsigned char` std::vector<unsigned char>::push_back() expects. These two helpers do the
    // conversion once, in C++, so scripts never need to build/read a byte vector one char at a time.
    chai_.add(chaiscript::fun([](const std::string& text)
    {
        return std::vector<unsigned char>(text.begin(), text.end());
    }), "ToBytes");

    chai_.add(chaiscript::fun([](const std::vector<unsigned char>& bytes)
    {
        return std::string(bytes.begin(), bytes.end());
    }), "ToStringFromBytes");

    // ErrorCode / CScriptException -- scripts see a raised exception whose message is
    // CScriptException::what(); these named constants let a script recognize the family of errors
    // this SDK can raise if it inspects the message.
    chai_.add_global_const(chaiscript::const_var(NO_ERROR), "NO_ERROR");
    chai_.add_global_const(chaiscript::const_var(NOT_IMPLEMENTED), "NOT_IMPLEMENTED");
    chai_.add_global_const(chaiscript::const_var(UNEXPECTED_ERROR), "UNEXPECTED_ERROR");
    chai_.add_global_const(chaiscript::const_var(BUFFER_TOO_SMALL), "BUFFER_TOO_SMALL");
    chai_.add_global_const(chaiscript::const_var(INVALID_ARGUMENT), "INVALID_ARGUMENT");
    chai_.add_global_const(chaiscript::const_var(FILE_IO_ERROR), "FILE_IO_ERROR");
    chai_.add_global_const(chaiscript::const_var(INVALID_DATA), "INVALID_DATA");
    chai_.add_global_const(chaiscript::const_var(OPERATION_CANCELLED), "OPERATION_CANCELLED");

#ifndef DLL_RUNNER
    chai_.add_global_const(chaiscript::const_var(PROVIDER_MICROSOFT), "PROVIDER_MICROSOFT");
    chai_.add_global_const(chaiscript::const_var(PROVIDER_CRYPTOPP), "PROVIDER_CRYPTOPP");
    chai_.add_global_const(chaiscript::const_var(PROVIDER_BOTAN), "PROVIDER_BOTAN");
    chai_.add_global_const(chaiscript::const_var(PROVIDER_OPENSSL), "PROVIDER_OPENSSL");
    chai_.add_global_const(chaiscript::const_var(PROVIDER_LIBGCRYPT), "PROVIDER_LIBGCRYPT");

    chai_.add_global_const(chaiscript::const_var(AEAD_AES_128_GCM), "AEAD_AES_128_GCM");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_192_GCM), "AEAD_AES_192_GCM");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_256_GCM), "AEAD_AES_256_GCM");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_128_CCM), "AEAD_AES_128_CCM");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_192_CCM), "AEAD_AES_192_CCM");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_256_CCM), "AEAD_AES_256_CCM");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_128_EAX), "AEAD_AES_128_EAX");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_192_EAX), "AEAD_AES_192_EAX");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_256_EAX), "AEAD_AES_256_EAX");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_128_SIV), "AEAD_AES_128_SIV");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_256_SIV), "AEAD_AES_256_SIV");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_128_GCM_SIV), "AEAD_AES_128_GCM_SIV");
    chai_.add_global_const(chaiscript::const_var(AEAD_AES_256_GCM_SIV), "AEAD_AES_256_GCM_SIV");
    chai_.add_global_const(chaiscript::const_var(AEAD_CHACHA20_POLY1305), "AEAD_CHACHA20_POLY1305");
    chai_.add_global_const(chaiscript::const_var(AEAD_TWOFISH_GCM), "AEAD_TWOFISH_GCM");
    chai_.add_global_const(chaiscript::const_var(AEAD_SERPENT_GCM), "AEAD_SERPENT_GCM");
    chai_.add_global_const(chaiscript::const_var(AEAD_CAMELLIA_GCM), "AEAD_CAMELLIA_GCM");

    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_128_CBC), "LEGACY_AES_128_CBC");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_192_CBC), "LEGACY_AES_192_CBC");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_256_CBC), "LEGACY_AES_256_CBC");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_128_CTR), "LEGACY_AES_128_CTR");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_192_CTR), "LEGACY_AES_192_CTR");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_256_CTR), "LEGACY_AES_256_CTR");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_128_CFB), "LEGACY_AES_128_CFB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_192_CFB), "LEGACY_AES_192_CFB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_256_CFB), "LEGACY_AES_256_CFB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_128_OFB), "LEGACY_AES_128_OFB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_192_OFB), "LEGACY_AES_192_OFB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_256_OFB), "LEGACY_AES_256_OFB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_128_ECB), "LEGACY_AES_128_ECB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_192_ECB), "LEGACY_AES_192_ECB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_AES_256_ECB), "LEGACY_AES_256_ECB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_RC2_CBC), "LEGACY_RC2_CBC");
    chai_.add_global_const(chaiscript::const_var(LEGACY_RC2_ECB), "LEGACY_RC2_ECB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_DES_CBC), "LEGACY_DES_CBC");
    chai_.add_global_const(chaiscript::const_var(LEGACY_DES_ECB), "LEGACY_DES_ECB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_3DES_CBC), "LEGACY_3DES_CBC");
    chai_.add_global_const(chaiscript::const_var(LEGACY_3DES_ECB), "LEGACY_3DES_ECB");
    chai_.add_global_const(chaiscript::const_var(LEGACY_RC4), "LEGACY_RC4");

    chai_.add_global_const(chaiscript::const_var(ASYMMETRIC_RSA_1024), "ASYMMETRIC_RSA_1024");
    chai_.add_global_const(chaiscript::const_var(ASYMMETRIC_RSA_2048), "ASYMMETRIC_RSA_2048");
    chai_.add_global_const(chaiscript::const_var(ASYMMETRIC_RSA_3072), "ASYMMETRIC_RSA_3072");
    chai_.add_global_const(chaiscript::const_var(ASYMMETRIC_RSA_4096), "ASYMMETRIC_RSA_4096");

    chai_.add_global_const(chaiscript::const_var(HASH_MD5), "HASH_MD5");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA1), "HASH_SHA1");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA224), "HASH_SHA224");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA256), "HASH_SHA256");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA384), "HASH_SHA384");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA512), "HASH_SHA512");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA512_256), "HASH_SHA512_256");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA3_224), "HASH_SHA3_224");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA3_256), "HASH_SHA3_256");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA3_384), "HASH_SHA3_384");
    chai_.add_global_const(chaiscript::const_var(HASH_SHA3_512), "HASH_SHA3_512");
    chai_.add_global_const(chaiscript::const_var(HASH_BLAKE2B), "HASH_BLAKE2B");
    chai_.add_global_const(chaiscript::const_var(HASH_BLAKE2S), "HASH_BLAKE2S");
    chai_.add_global_const(chaiscript::const_var(HASH_RIPEMD160), "HASH_RIPEMD160");

    chai_.add_global_const(chaiscript::const_var(SIGNATURE_RSA_PSS_SHA256_2048), "SIGNATURE_RSA_PSS_SHA256_2048");
    chai_.add_global_const(chaiscript::const_var(SIGNATURE_RSA_PSS_SHA256_3072), "SIGNATURE_RSA_PSS_SHA256_3072");
    chai_.add_global_const(chaiscript::const_var(SIGNATURE_RSA_PSS_SHA256_4096), "SIGNATURE_RSA_PSS_SHA256_4096");
    chai_.add_global_const(chaiscript::const_var(SIGNATURE_ECDSA_P256_SHA256), "SIGNATURE_ECDSA_P256_SHA256");
    chai_.add_global_const(chaiscript::const_var(SIGNATURE_ED25519), "SIGNATURE_ED25519");
    chai_.add_global_const(chaiscript::const_var(SIGNATURE_ECDSA_P384_SHA384), "SIGNATURE_ECDSA_P384_SHA384");
    chai_.add_global_const(chaiscript::const_var(SIGNATURE_ECDSA_P521_SHA512), "SIGNATURE_ECDSA_P521_SHA512");
    chai_.add_global_const(chaiscript::const_var(SIGNATURE_DSA_SHA256_2048), "SIGNATURE_DSA_SHA256_2048");
    chai_.add_global_const(chaiscript::const_var(SIGNATURE_DSA_SHA256_3072), "SIGNATURE_DSA_SHA256_3072");

    chai_.add_global_const(chaiscript::const_var(KEYAGREEMENT_ECDH_P256), "KEYAGREEMENT_ECDH_P256");
    chai_.add_global_const(chaiscript::const_var(KEYAGREEMENT_X25519), "KEYAGREEMENT_X25519");

    chai_.add_global_const(chaiscript::const_var(RANDOM_SYSTEM), "RANDOM_SYSTEM");
    chai_.add_global_const(chaiscript::const_var(RANDOM_HASH_DRBG), "RANDOM_HASH_DRBG");
    chai_.add_global_const(chaiscript::const_var(RANDOM_HMAC_DRBG), "RANDOM_HMAC_DRBG");
    chai_.add_global_const(chaiscript::const_var(RANDOM_CTR_DRBG), "RANDOM_CTR_DRBG");

    chai_.add_global_const(chaiscript::const_var(PGP_KEY_ALGORITHM_RSA), "PGP_KEY_ALGORITHM_RSA");
    chai_.add_global_const(chaiscript::const_var(PGP_KEY_ALGORITHM_ED25519_X25519), "PGP_KEY_ALGORITHM_ED25519_X25519");

    // Deliberately two distinct constant names, never merged -- PgpFileCompressionAlgorithm
    // (CPgpEngine) and PgpCompressionAlgorithm (CPgpEngineWrapper) share the same namespace but have
    // different values for the same names (see PgpEngine.h/PgpEngineWrapper.h's own comments).
    chai_.add_global_const(chaiscript::const_var(PGP_FILE_COMPRESSION_ALGORITHM_ZIP), "PGP_FILE_COMPRESSION_ALGORITHM_ZIP");
    chai_.add_global_const(chaiscript::const_var(PGP_FILE_COMPRESSION_ALGORITHM_ZLIB), "PGP_FILE_COMPRESSION_ALGORITHM_ZLIB");

    chai_.add_global_const(chaiscript::const_var(PGP_COMPRESSION_ALGORITHM_NONE), "PGP_COMPRESSION_ALGORITHM_NONE");
    chai_.add_global_const(chaiscript::const_var(PGP_COMPRESSION_ALGORITHM_ZIP), "PGP_COMPRESSION_ALGORITHM_ZIP");
    chai_.add_global_const(chaiscript::const_var(PGP_COMPRESSION_ALGORITHM_ZLIB), "PGP_COMPRESSION_ALGORITHM_ZLIB");
    chai_.add_global_const(chaiscript::const_var(PGP_COMPRESSION_ALGORITHM_BZIP2), "PGP_COMPRESSION_ALGORITHM_BZIP2");

    chai_.add_global_const(chaiscript::const_var(PGP_COMPRESSION_NOT_PRESENT), "PGP_COMPRESSION_NOT_PRESENT");
    chai_.add_global_const(chaiscript::const_var(PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION), "PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION");

    chai_.add_global_const(chaiscript::const_var(PGP_INSPECTION_KEY_ID_RECORD_SIZE), "PGP_INSPECTION_KEY_ID_RECORD_SIZE");
    chai_.add_global_const(chaiscript::const_var(PGP_INSPECTION_SIGNATURE_RECORD_SIZE), "PGP_INSPECTION_SIGNATURE_RECORD_SIZE");

    chai_.add(chaiscript::user_type<CScriptCryptoApi>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi()>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const AeadAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const HashAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const AsymmetricAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const LegacySymmetricAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const SignatureAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const KeyAgreementAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm, const SignatureAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::constructor<CScriptCryptoApi(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm, const SignatureAlgorithm, const KeyAgreementAlgorithm)>(), "CryptoApi");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GetVersion), "GetVersion");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::EncryptBuffer), "EncryptBuffer");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::DecryptBuffer), "DecryptBuffer");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::EncryptBytes), "EncryptBytes");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::DecryptBytes), "DecryptBytes");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::EncryptString), "EncryptString");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::DecryptString), "DecryptString");
    chai_.add(chaiscript::fun(static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&)>(&CScriptCryptoApi::EncryptFile)), "EncryptFile");
    chai_.add(chaiscript::fun(static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&)>(&CScriptCryptoApi::DecryptFile)), "DecryptFile");
    // C++-calls-INTO-script direction: ChaiScript converts a boxed script function into a
    // std::function<Sig> automatically when the bound overload's parameter has that exact type
    // (no custom Stack<T>-style specialization needed, unlike LuaBridge3) -- called once per
    // chunk from inside EncryptFile/DecryptFile's own C++ loop.
    chai_.add(chaiscript::fun(static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&, const CryptoApiNS::ScriptProgressCallback&)>(&CScriptCryptoApi::EncryptFile)), "EncryptFileWithProgress");
    chai_.add(chaiscript::fun(static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&, const CryptoApiNS::ScriptProgressCallback&)>(&CScriptCryptoApi::DecryptFile)), "DecryptFileWithProgress");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GenerateAsymmetricKeyPair), "GenerateAsymmetricKeyPair");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GetMaxAsymmetricPlaintextSize), "GetMaxAsymmetricPlaintextSize");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GetAsymmetricCiphertextSize), "GetAsymmetricCiphertextSize");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::EncryptWithPublicKey), "EncryptWithPublicKey");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::DecryptWithPrivateKey), "DecryptWithPrivateKey");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::EncryptLegacyBuffer), "EncryptLegacyBuffer");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::DecryptLegacyBuffer), "DecryptLegacyBuffer");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GetHashSize), "GetHashSize");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::ComputeHashBuffer), "ComputeHashBuffer");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::ComputeHashBytes), "ComputeHashBytes");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::ComputeHashString), "ComputeHashString");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::ComputeHashFile), "ComputeHashFile");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GenerateSignatureKeyPair), "GenerateSignatureKeyPair");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GetSignatureSize), "GetSignatureSize");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::SignBuffer), "SignBuffer");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::VerifyBuffer), "VerifyBuffer");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GenerateKeyAgreementKeyPair), "GenerateKeyAgreementKeyPair");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GetKeyAgreementPublicKeySize), "GetKeyAgreementPublicKeySize");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::GetSharedSecretSize), "GetSharedSecretSize");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::ExportKeyAgreementPublicKey), "ExportKeyAgreementPublicKey");
    chai_.add(chaiscript::fun(&CScriptCryptoApi::DeriveSharedSecret), "DeriveSharedSecret");
    chai_.add(chaiscript::fun(static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const int)>(&CScriptCryptoApi::GenerateRandomBytes)), "GenerateRandomBytes");
    chai_.add(chaiscript::fun(static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const RandomAlgorithm, const int)>(&CScriptCryptoApi::GenerateRandomBytes)), "GenerateRandomBytes");

    chai_.add(chaiscript::user_type<CScriptPgpEngine>(), "PgpEngine");
    chai_.add(chaiscript::constructor<CScriptPgpEngine()>(), "PgpEngine");
    chai_.add(chaiscript::constructor<CScriptPgpEngine(const int)>(), "PgpEngine");
    chai_.add(chaiscript::constructor<CScriptPgpEngine(const PgpKeyAlgorithm)>(), "PgpEngine");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::GetKeyAlgorithm), "GetKeyAlgorithm");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngine::*)(const std::string&, const std::string&)>(&CScriptPgpEngine::GenerateKeyPair)), "GenerateKeyPair");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngine::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngine::GenerateKeyPair)), "GenerateKeyPair");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::GetKeyExpirationSeconds), "GetKeyExpirationSeconds");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::ExportPublicKeyArmored), "ExportPublicKeyArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::ExportSecretKeyArmored), "ExportSecretKeyArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::GetKeyId), "GetKeyId");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::RevokeKeyArmored), "RevokeKeyArmored");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngine::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngine::ImportPeerPublicKey)), "ImportPeerPublicKey");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportPeerPublicKey)), "ImportPeerPublicKey");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::GetPeerKeyId), "GetPeerKeyId");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngine::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngine::ImportAdditionalRecipientPublicKey)), "ImportAdditionalRecipientPublicKey");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportAdditionalRecipientPublicKey)), "ImportAdditionalRecipientPublicKey");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::EncryptBuffer), "EncryptBuffer");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::EncryptStringArmored), "EncryptStringArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::DecryptBuffer), "DecryptBuffer");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::DecryptStringArmored), "DecryptStringArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::SignBuffer), "SignBuffer");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::VerifyBuffer), "VerifyBuffer");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::ClearSignString), "ClearSignString");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::VerifyClearSignedString), "VerifyClearSignedString");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::EncryptFile), "EncryptFile");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::EncryptFileCompressed), "EncryptFileCompressed");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::DecryptFile), "DecryptFile");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::SignFile), "SignFile");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::VerifyFile), "VerifyFile");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::IsPublicKeyEncrypted), "IsPublicKeyEncrypted");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::IsPasswordEncrypted), "IsPasswordEncrypted");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::IsIntegrityProtected), "IsIntegrityProtected");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::GetCompression), "GetCompression");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::ListEncryptionKeyIds), "ListEncryptionKeyIds");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::ListSigningKeyIds), "ListSigningKeyIds");
    chai_.add(chaiscript::fun(&CScriptPgpEngine::ListSignatures), "ListSignatures");

    chai_.add(chaiscript::user_type<CScriptPgpEngineWrapper>(), "PgpEngineWrapper");
    chai_.add(chaiscript::constructor<CScriptPgpEngineWrapper()>(), "PgpEngineWrapper");
    chai_.add(chaiscript::constructor<CScriptPgpEngineWrapper(const int)>(), "PgpEngineWrapper");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::IsGnuPgAvailable), "IsGnuPgAvailable");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&)>(&CScriptPgpEngineWrapper::GenerateKeyPair)), "GenerateKeyPair");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngineWrapper::GenerateKeyPair)), "GenerateKeyPair");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&)>(&CScriptPgpEngineWrapper::GenerateKeyPairEcc)), "GenerateKeyPairEcc");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngineWrapper::GenerateKeyPairEcc)), "GenerateKeyPairEcc");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetKeyExpirationSeconds), "GetKeyExpirationSeconds");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::ExportPublicKeyArmored), "ExportPublicKeyArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::ExportSecretKeyArmored), "ExportSecretKeyArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetKeyId), "GetKeyId");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::RevokeKeyArmored), "RevokeKeyArmored");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngineWrapper::ImportPeerPublicKey)), "ImportPeerPublicKey");
    chai_.add(chaiscript::fun(static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&)>(&CScriptPgpEngineWrapper::ImportPeerPublicKey)), "ImportPeerPublicKey");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetPeerKeyId), "GetPeerKeyId");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetImportedPeerKeyCount), "GetImportedPeerKeyCount");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetImportedPeerKeyId), "GetImportedPeerKeyId");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetKeyringListing), "GetKeyringListing");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetKeyringKeyCount), "GetKeyringKeyCount");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetKeyringKeyId), "GetKeyringKeyId");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::DeletePeerPublicKey), "DeletePeerPublicKey");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::DeleteOwnIdentity), "DeleteOwnIdentity");
    chai_.add(chaiscript::fun(static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngineWrapper::EncryptBuffer)), "EncryptBuffer");
    chai_.add(chaiscript::fun(static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptBuffer)), "EncryptBuffer");
    chai_.add(chaiscript::fun(static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&)>(&CScriptPgpEngineWrapper::EncryptStringArmored)), "EncryptStringArmored");
    chai_.add(chaiscript::fun(static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptStringArmored)), "EncryptStringArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::EncryptBufferSymmetric), "EncryptBufferSymmetric");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::EncryptStringArmoredSymmetric), "EncryptStringArmoredSymmetric");
    chai_.add(chaiscript::fun(static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const std::vector<std::string>&)>(&CScriptPgpEngineWrapper::EncryptBufferMultiRecipient)), "EncryptBufferMultiRecipient");
    chai_.add(chaiscript::fun(static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const std::vector<std::string>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptBufferMultiRecipient)), "EncryptBufferMultiRecipient");
    chai_.add(chaiscript::fun(static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const std::vector<std::string>&)>(&CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient)), "EncryptStringArmoredMultiRecipient");
    chai_.add(chaiscript::fun(static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const std::vector<std::string>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient)), "EncryptStringArmoredMultiRecipient");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::DecryptBuffer), "DecryptBuffer");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::DecryptStringArmored), "DecryptStringArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::SignBuffer), "SignBuffer");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::VerifyBuffer), "VerifyBuffer");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::ClearSignString), "ClearSignString");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::VerifyClearSignedString), "VerifyClearSignedString");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::EncryptFile), "EncryptFile");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::DecryptFile), "DecryptFile");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::SignFile), "SignFile");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::VerifyFile), "VerifyFile");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::IsPublicKeyEncrypted), "IsPublicKeyEncrypted");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::IsPasswordEncrypted), "IsPasswordEncrypted");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::IsIntegrityProtected), "IsIntegrityProtected");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::GetCompression), "GetCompression");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::ListEncryptionKeyIds), "ListEncryptionKeyIds");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::ListSigningKeyIds), "ListSigningKeyIds");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapper::ListSignatures), "ListSignatures");
#endif // !DLL_RUNNER

    // DLL-hosted facades (CScriptCryptoApiDll/CScriptPgpEngineDll/CScriptPgpEngineWrapperDll) --
    // lightweight, no CCryptoApi/CPgpEngine/CPgpEngineWrapper dependency, so registered
    // unconditionally (harmless for AppBuilder, required for DllRunner). No constructor is added
    // -- these are only ever pushed as an already-constructed instance via SetDllCryptoApi/
    // SetDllPgpEngine/SetDllPgpEngineWrapper below, never a script's own constructor call.
    chai_.add(chaiscript::user_type<CScriptCryptoApiDll>(), "CryptoApiDll");
    chai_.add(chaiscript::fun(&CScriptCryptoApiDll::GetVersion), "GetVersion");
    chai_.add(chaiscript::fun(&CScriptCryptoApiDll::GetHashSize), "GetHashSize");
    chai_.add(chaiscript::fun(&CScriptCryptoApiDll::ComputeHashString), "ComputeHashString");
    chai_.add(chaiscript::fun(&CScriptCryptoApiDll::EncryptFile), "EncryptFileWithProgress");
    chai_.add(chaiscript::fun(&CScriptCryptoApiDll::DecryptFile), "DecryptFileWithProgress");

    chai_.add(chaiscript::user_type<CScriptPgpEngineDll>(), "PgpEngineDll");
    chai_.add(chaiscript::fun(&CScriptPgpEngineDll::GenerateKeyPair), "GenerateKeyPair");
    chai_.add(chaiscript::fun(&CScriptPgpEngineDll::ExportPublicKeyArmored), "ExportPublicKeyArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngineDll::ImportPeerPublicKey), "ImportPeerPublicKey");
    chai_.add(chaiscript::fun(&CScriptPgpEngineDll::EncryptStringArmored), "EncryptStringArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngineDll::DecryptStringArmored), "DecryptStringArmored");

    chai_.add(chaiscript::user_type<CScriptPgpEngineWrapperDll>(), "PgpEngineWrapperDll");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapperDll::IsGnuPgAvailable), "IsGnuPgAvailable");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapperDll::GenerateKeyPair), "GenerateKeyPair");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapperDll::ExportPublicKeyArmored), "ExportPublicKeyArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapperDll::ImportPeerPublicKey), "ImportPeerPublicKey");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapperDll::EncryptStringArmored), "EncryptStringArmored");
    chai_.add(chaiscript::fun(&CScriptPgpEngineWrapperDll::DecryptStringArmored), "DecryptStringArmored");
}
// -----------------------------------------------------------------------------

void CChaiScriptEngine::SetDllCryptoApi(CScriptCryptoApiDll* api)
{
    try
    {
        chai_.add_global(chaiscript::var(api), "cryptoApi");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CChaiScriptEngine::SetDllPgpEngine(CScriptPgpEngineDll* engine)
{
    try
    {
        chai_.add_global(chaiscript::var(engine), "pgpEngine");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CChaiScriptEngine::SetDllPgpEngineWrapper(CScriptPgpEngineWrapperDll* wrapper)
{
    try
    {
        chai_.add_global(chaiscript::var(wrapper), "pgpEngineWrapper");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

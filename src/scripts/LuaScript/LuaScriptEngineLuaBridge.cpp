#include "LuaScriptEngineLuaBridge.h"
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

#include "Definitions/Definitions.h"

extern "C"
{
#include <lauxlib.h>
#include <lualib.h>
}

#include <LuaBridge/LuaBridge.h>

#include <type_traits>
#include <utility>
#include <vector>

// LuaScriptEngineLuaBridgeLegacy.cpp (LuaBridge 2.10) renames ITS OWN "luabridge" namespace to
// "luabridge_legacy" via a preprocessor macro before including its headers, specifically so the
// two vendored library versions -- which otherwise both declare classes with the exact same
// fully-qualified names (luabridge::Namespace, luabridge::Registrar, luabridge::Stack<T>, etc.,
// with DIFFERENT, incompatible implementations) -- never collide at link time. See that file's own
// comment for the full rationale and the exact symptom the collision caused before this fix
// ("Assertion failed: popsCount <= lua_gettop(L)" from LuaBridge3's own Registrar destructor,
// firing well after every LuaBridge3 test had already reported PASSED). This file (LuaBridge3)
// keeps the real, unrenamed "luabridge" namespace.

// Unchecked integer<->enum conversion for every enum this SDK exposes to Lua -- lets bound methods
// take/return these enum types directly as plain Lua integers. LuaBridge3's own Stack<T> contract
// (unlike LuaBridge 2.10's simpler void push()/T get()) is push() returning Result and get()
// returning TypeResult<T>; each specialization below delegates to Stack<underlying int type>, which
// already implements that contract, exactly mirroring what LuaBridge3's own luabridge::Enum<T>
// helper does internally. Written out directly rather than inheriting from Enum<T> itself: MSVC
// (19.44) fails to parse "struct Stack<X> : Enum<X> {};" here with C7568/C3770 ("argument list
// missing after assumed function template 'Enum'"), cascading spurious errors through the rest of
// this translation unit -- reimplementing the same logic inline sidesteps it. One block per enum
// (not templated/macroed) to match this repo's explicit, non-DRY style.
#ifndef DLL_RUNNER

namespace luabridge
{

template <> struct Stack<CryptoApiNS::ErrorCode>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::ErrorCode>;
    static Result push(lua_State* L, CryptoApiNS::ErrorCode value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::ErrorCode> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::ErrorCode>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::ProviderKind>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::ProviderKind>;
    static Result push(lua_State* L, CryptoApiNS::ProviderKind value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::ProviderKind> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::ProviderKind>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::AeadAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::AeadAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::AeadAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::AeadAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::AeadAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::LegacySymmetricAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::LegacySymmetricAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::LegacySymmetricAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::LegacySymmetricAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::LegacySymmetricAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::AsymmetricAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::AsymmetricAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::AsymmetricAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::AsymmetricAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::AsymmetricAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::HashAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::HashAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::HashAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::HashAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::HashAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::SignatureAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::SignatureAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::SignatureAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::SignatureAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::SignatureAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::KeyAgreementAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::KeyAgreementAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::KeyAgreementAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::KeyAgreementAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::KeyAgreementAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::RandomAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::RandomAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::RandomAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::RandomAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::RandomAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::PgpKeyAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::PgpKeyAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::PgpKeyAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::PgpKeyAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::PgpKeyAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::PgpFileCompressionAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::PgpFileCompressionAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::PgpFileCompressionAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::PgpFileCompressionAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::PgpFileCompressionAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::PgpCompressionAlgorithm>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::PgpCompressionAlgorithm>;
    static Result push(lua_State* L, CryptoApiNS::PgpCompressionAlgorithm value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::PgpCompressionAlgorithm> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::PgpCompressionAlgorithm>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::PgpCompressionInspectionResult>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::PgpCompressionInspectionResult>;
    static Result push(lua_State* L, CryptoApiNS::PgpCompressionInspectionResult value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::PgpCompressionInspectionResult> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::PgpCompressionInspectionResult>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

template <> struct Stack<CryptoApiNS::PgpInspectionRecordSize>
{
    using Underlying = std::underlying_type_t<CryptoApiNS::PgpInspectionRecordSize>;
    static Result push(lua_State* L, CryptoApiNS::PgpInspectionRecordSize value) { return Stack<Underlying>::push(L, static_cast<Underlying>(value)); }
    static TypeResult<CryptoApiNS::PgpInspectionRecordSize> get(lua_State* L, int index) { auto result = Stack<Underlying>::get(L, index); if (!result) return result.error(); return static_cast<CryptoApiNS::PgpInspectionRecordSize>(*result); }
    static bool isInstance(lua_State* L, int index) { return Stack<Underlying>::isInstance(L, index); }
};

} // namespace luabridge

#endif // !DLL_RUNNER

namespace
{

// Pushes a read-only-by-convention Lua global table of name->integer constants -- the LuaBridge
// counterpart of CLuaScriptEngine's sol2 new_enum() calls. Uses the raw Lua C API directly rather
// than LuaBridge's Namespace::addProperty (which is a getter/setter property mechanism, not a
// plain constant-table registrar).
void pushEnumTable(lua_State* luaState, const char* globalName, const std::vector<std::pair<const char*, int>>& entries)
{
    lua_createtable(luaState, 0, static_cast<int>(entries.size()));
    for (const auto& entry : entries)
    {
        lua_pushinteger(luaState, entry.second);
        lua_setfield(luaState, -2, entry.first);
    }
    lua_setglobal(luaState, globalName);
}
// -----------------------------------------------------------------------------

} // namespace

namespace CryptoApiNS
{

CLuaScriptEngineLuaBridge::~CLuaScriptEngineLuaBridge()
{
    lua_close(luaState_);
}
// -----------------------------------------------------------------------------

CLuaScriptEngineLuaBridge::CLuaScriptEngineLuaBridge() : luaState_(luaL_newstate())
{
    luaL_requiref(luaState_, LUA_GNAME, luaopen_base, 1);
    lua_pop(luaState_, 1);
    luaL_requiref(luaState_, LUA_STRLIBNAME, luaopen_string, 1);
    lua_pop(luaState_, 1);
    luaL_requiref(luaState_, LUA_MATHLIBNAME, luaopen_math, 1);
    lua_pop(luaState_, 1);
    luaL_requiref(luaState_, LUA_TABLIBNAME, luaopen_table, 1);
    lua_pop(luaState_, 1);
    luaL_requiref(luaState_, LUA_COLIBNAME, luaopen_coroutine, 1);
    lua_pop(luaState_, 1);

    registerBindings();
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridge::RunFile(const std::string& filePath)
{
    if (luaL_dofile(luaState_, filePath.c_str()) != 0)
    {
        const char* message = lua_tostring(luaState_, -1);
        std::string errorMessage = message ? message : "unknown Lua error";
        lua_pop(luaState_, 1);
        throw CScriptException(UNEXPECTED_ERROR, std::string("RunFile: ") + errorMessage);
    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridge::RunString(const std::string& code)
{
    if (luaL_dostring(luaState_, code.c_str()) != 0)
    {
        const char* message = lua_tostring(luaState_, -1);
        std::string errorMessage = message ? message : "unknown Lua error";
        lua_pop(luaState_, 1);
        throw CScriptException(UNEXPECTED_ERROR, std::string("RunString: ") + errorMessage);
    }
}
// -----------------------------------------------------------------------------

bool CLuaScriptEngineLuaBridge::GetGlobalBool(const std::string& name) const
{
    try
    {
        lua_getglobal(luaState_, name.c_str());
        bool value = lua_toboolean(luaState_, -1) != 0;
        lua_pop(luaState_, 1);
        return value;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

int CLuaScriptEngineLuaBridge::GetGlobalInt(const std::string& name) const
{
    try
    {
        lua_getglobal(luaState_, name.c_str());
        int value = static_cast<int>(lua_tointeger(luaState_, -1));
        lua_pop(luaState_, 1);
        return value;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::string CLuaScriptEngineLuaBridge::GetGlobalString(const std::string& name) const
{
    try
    {
        lua_getglobal(luaState_, name.c_str());
        const char* value = lua_tostring(luaState_, -1);
        std::string result = value ? value : "";
        lua_pop(luaState_, 1);
        return result;
    }
    catch (...)
    {
        return std::string();
    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridge::registerBindings(void)
{
#ifndef DLL_RUNNER
    pushEnumTable(luaState_, "ErrorCode", {
        {"NO_ERROR", NO_ERROR},
        {"NOT_IMPLEMENTED", NOT_IMPLEMENTED},
        {"UNEXPECTED_ERROR", UNEXPECTED_ERROR},
        {"BUFFER_TOO_SMALL", BUFFER_TOO_SMALL},
        {"INVALID_ARGUMENT", INVALID_ARGUMENT},
        {"FILE_IO_ERROR", FILE_IO_ERROR},
        {"INVALID_DATA", INVALID_DATA},
        {"OPERATION_CANCELLED", OPERATION_CANCELLED}});

    pushEnumTable(luaState_, "ProviderKind", {
        {"PROVIDER_MICROSOFT", PROVIDER_MICROSOFT},
        {"PROVIDER_CRYPTOPP", PROVIDER_CRYPTOPP},
        {"PROVIDER_BOTAN", PROVIDER_BOTAN},
        {"PROVIDER_OPENSSL", PROVIDER_OPENSSL},
        {"PROVIDER_LIBGCRYPT", PROVIDER_LIBGCRYPT}});

    pushEnumTable(luaState_, "AeadAlgorithm", {
        {"AEAD_AES_128_GCM", AEAD_AES_128_GCM},
        {"AEAD_AES_192_GCM", AEAD_AES_192_GCM},
        {"AEAD_AES_256_GCM", AEAD_AES_256_GCM},
        {"AEAD_AES_128_CCM", AEAD_AES_128_CCM},
        {"AEAD_AES_192_CCM", AEAD_AES_192_CCM},
        {"AEAD_AES_256_CCM", AEAD_AES_256_CCM},
        {"AEAD_AES_128_EAX", AEAD_AES_128_EAX},
        {"AEAD_AES_192_EAX", AEAD_AES_192_EAX},
        {"AEAD_AES_256_EAX", AEAD_AES_256_EAX},
        {"AEAD_AES_128_SIV", AEAD_AES_128_SIV},
        {"AEAD_AES_256_SIV", AEAD_AES_256_SIV},
        {"AEAD_AES_128_GCM_SIV", AEAD_AES_128_GCM_SIV},
        {"AEAD_AES_256_GCM_SIV", AEAD_AES_256_GCM_SIV},
        {"AEAD_CHACHA20_POLY1305", AEAD_CHACHA20_POLY1305},
        {"AEAD_TWOFISH_GCM", AEAD_TWOFISH_GCM},
        {"AEAD_SERPENT_GCM", AEAD_SERPENT_GCM},
        {"AEAD_CAMELLIA_GCM", AEAD_CAMELLIA_GCM}});

    pushEnumTable(luaState_, "LegacySymmetricAlgorithm", {
        {"LEGACY_AES_128_CBC", LEGACY_AES_128_CBC},
        {"LEGACY_AES_192_CBC", LEGACY_AES_192_CBC},
        {"LEGACY_AES_256_CBC", LEGACY_AES_256_CBC},
        {"LEGACY_AES_128_CTR", LEGACY_AES_128_CTR},
        {"LEGACY_AES_192_CTR", LEGACY_AES_192_CTR},
        {"LEGACY_AES_256_CTR", LEGACY_AES_256_CTR},
        {"LEGACY_AES_128_CFB", LEGACY_AES_128_CFB},
        {"LEGACY_AES_192_CFB", LEGACY_AES_192_CFB},
        {"LEGACY_AES_256_CFB", LEGACY_AES_256_CFB},
        {"LEGACY_AES_128_OFB", LEGACY_AES_128_OFB},
        {"LEGACY_AES_192_OFB", LEGACY_AES_192_OFB},
        {"LEGACY_AES_256_OFB", LEGACY_AES_256_OFB},
        {"LEGACY_AES_128_ECB", LEGACY_AES_128_ECB},
        {"LEGACY_AES_192_ECB", LEGACY_AES_192_ECB},
        {"LEGACY_AES_256_ECB", LEGACY_AES_256_ECB},
        {"LEGACY_RC2_CBC", LEGACY_RC2_CBC},
        {"LEGACY_RC2_ECB", LEGACY_RC2_ECB},
        {"LEGACY_DES_CBC", LEGACY_DES_CBC},
        {"LEGACY_DES_ECB", LEGACY_DES_ECB},
        {"LEGACY_3DES_CBC", LEGACY_3DES_CBC},
        {"LEGACY_3DES_ECB", LEGACY_3DES_ECB},
        {"LEGACY_RC4", LEGACY_RC4}});

    pushEnumTable(luaState_, "AsymmetricAlgorithm", {
        {"ASYMMETRIC_RSA_1024", ASYMMETRIC_RSA_1024},
        {"ASYMMETRIC_RSA_2048", ASYMMETRIC_RSA_2048},
        {"ASYMMETRIC_RSA_3072", ASYMMETRIC_RSA_3072},
        {"ASYMMETRIC_RSA_4096", ASYMMETRIC_RSA_4096}});

    pushEnumTable(luaState_, "HashAlgorithm", {
        {"HASH_MD5", HASH_MD5},
        {"HASH_SHA1", HASH_SHA1},
        {"HASH_SHA224", HASH_SHA224},
        {"HASH_SHA256", HASH_SHA256},
        {"HASH_SHA384", HASH_SHA384},
        {"HASH_SHA512", HASH_SHA512},
        {"HASH_SHA512_256", HASH_SHA512_256},
        {"HASH_SHA3_224", HASH_SHA3_224},
        {"HASH_SHA3_256", HASH_SHA3_256},
        {"HASH_SHA3_384", HASH_SHA3_384},
        {"HASH_SHA3_512", HASH_SHA3_512},
        {"HASH_BLAKE2B", HASH_BLAKE2B},
        {"HASH_BLAKE2S", HASH_BLAKE2S},
        {"HASH_RIPEMD160", HASH_RIPEMD160}});

    pushEnumTable(luaState_, "SignatureAlgorithm", {
        {"SIGNATURE_RSA_PSS_SHA256_2048", SIGNATURE_RSA_PSS_SHA256_2048},
        {"SIGNATURE_RSA_PSS_SHA256_3072", SIGNATURE_RSA_PSS_SHA256_3072},
        {"SIGNATURE_RSA_PSS_SHA256_4096", SIGNATURE_RSA_PSS_SHA256_4096},
        {"SIGNATURE_ECDSA_P256_SHA256", SIGNATURE_ECDSA_P256_SHA256},
        {"SIGNATURE_ED25519", SIGNATURE_ED25519},
        {"SIGNATURE_ECDSA_P384_SHA384", SIGNATURE_ECDSA_P384_SHA384},
        {"SIGNATURE_ECDSA_P521_SHA512", SIGNATURE_ECDSA_P521_SHA512},
        {"SIGNATURE_DSA_SHA256_2048", SIGNATURE_DSA_SHA256_2048},
        {"SIGNATURE_DSA_SHA256_3072", SIGNATURE_DSA_SHA256_3072}});

    pushEnumTable(luaState_, "KeyAgreementAlgorithm", {
        {"KEYAGREEMENT_ECDH_P256", KEYAGREEMENT_ECDH_P256},
        {"KEYAGREEMENT_X25519", KEYAGREEMENT_X25519}});

    pushEnumTable(luaState_, "RandomAlgorithm", {
        {"RANDOM_SYSTEM", RANDOM_SYSTEM},
        {"RANDOM_HASH_DRBG", RANDOM_HASH_DRBG},
        {"RANDOM_HMAC_DRBG", RANDOM_HMAC_DRBG},
        {"RANDOM_CTR_DRBG", RANDOM_CTR_DRBG}});

    pushEnumTable(luaState_, "PgpKeyAlgorithm", {
        {"PGP_KEY_ALGORITHM_RSA", PGP_KEY_ALGORITHM_RSA},
        {"PGP_KEY_ALGORITHM_ED25519_X25519", PGP_KEY_ALGORITHM_ED25519_X25519}});

    // Deliberately two distinct Lua enum tables, never merged -- see LuaScriptEngine.cpp's own
    // comment on PgpFileCompressionAlgorithm vs PgpCompressionAlgorithm for why.
    pushEnumTable(luaState_, "PgpFileCompressionAlgorithm", {
        {"PGP_FILE_COMPRESSION_ALGORITHM_ZIP", PGP_FILE_COMPRESSION_ALGORITHM_ZIP},
        {"PGP_FILE_COMPRESSION_ALGORITHM_ZLIB", PGP_FILE_COMPRESSION_ALGORITHM_ZLIB}});

    pushEnumTable(luaState_, "PgpCompressionAlgorithm", {
        {"PGP_COMPRESSION_ALGORITHM_NONE", PGP_COMPRESSION_ALGORITHM_NONE},
        {"PGP_COMPRESSION_ALGORITHM_ZIP", PGP_COMPRESSION_ALGORITHM_ZIP},
        {"PGP_COMPRESSION_ALGORITHM_ZLIB", PGP_COMPRESSION_ALGORITHM_ZLIB},
        {"PGP_COMPRESSION_ALGORITHM_BZIP2", PGP_COMPRESSION_ALGORITHM_BZIP2}});

    pushEnumTable(luaState_, "PgpCompressionInspectionResult", {
        {"PGP_COMPRESSION_NOT_PRESENT", PGP_COMPRESSION_NOT_PRESENT},
        {"PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION", PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION}});

    pushEnumTable(luaState_, "PgpInspectionRecordSize", {
        {"PGP_INSPECTION_KEY_ID_RECORD_SIZE", PGP_INSPECTION_KEY_ID_RECORD_SIZE},
        {"PGP_INSPECTION_SIGNATURE_RECORD_SIZE", PGP_INSPECTION_SIGNATURE_RECORD_SIZE}});

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptCryptoApi>("CryptoApi")
            .addConstructor<
                void (*)(),
                void (*)(const ProviderKind, const AeadAlgorithm),
                void (*)(const ProviderKind, const HashAlgorithm),
                void (*)(const ProviderKind, const AsymmetricAlgorithm),
                void (*)(const ProviderKind, const LegacySymmetricAlgorithm),
                void (*)(const ProviderKind, const SignatureAlgorithm),
                void (*)(const ProviderKind, const KeyAgreementAlgorithm),
                void (*)(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm),
                void (*)(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm),
                void (*)(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm),
                void (*)(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm, const SignatureAlgorithm),
                void (*)(const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm, const SignatureAlgorithm, const KeyAgreementAlgorithm)>()
            .addFunction("GetVersion", &CScriptCryptoApi::GetVersion)
            .addFunction("EncryptBuffer", &CScriptCryptoApi::EncryptBuffer)
            .addFunction("DecryptBuffer", &CScriptCryptoApi::DecryptBuffer)
            .addFunction("EncryptBytes", &CScriptCryptoApi::EncryptBytes)
            .addFunction("DecryptBytes", &CScriptCryptoApi::DecryptBytes)
            .addFunction("EncryptString", &CScriptCryptoApi::EncryptString)
            .addFunction("DecryptString", &CScriptCryptoApi::DecryptString)
            .addFunction("EncryptFile", &CScriptCryptoApi::EncryptFile)
            .addFunction("DecryptFile", &CScriptCryptoApi::DecryptFile)
            .addFunction("GenerateAsymmetricKeyPair", &CScriptCryptoApi::GenerateAsymmetricKeyPair)
            .addFunction("GetMaxAsymmetricPlaintextSize", &CScriptCryptoApi::GetMaxAsymmetricPlaintextSize)
            .addFunction("GetAsymmetricCiphertextSize", &CScriptCryptoApi::GetAsymmetricCiphertextSize)
            .addFunction("EncryptWithPublicKey", &CScriptCryptoApi::EncryptWithPublicKey)
            .addFunction("DecryptWithPrivateKey", &CScriptCryptoApi::DecryptWithPrivateKey)
            .addFunction("EncryptLegacyBuffer", &CScriptCryptoApi::EncryptLegacyBuffer)
            .addFunction("DecryptLegacyBuffer", &CScriptCryptoApi::DecryptLegacyBuffer)
            .addFunction("GetHashSize", &CScriptCryptoApi::GetHashSize)
            .addFunction("ComputeHashBuffer", &CScriptCryptoApi::ComputeHashBuffer)
            .addFunction("ComputeHashBytes", &CScriptCryptoApi::ComputeHashBytes)
            .addFunction("ComputeHashString", &CScriptCryptoApi::ComputeHashString)
            .addFunction("ComputeHashFile", &CScriptCryptoApi::ComputeHashFile)
            .addFunction("GenerateSignatureKeyPair", &CScriptCryptoApi::GenerateSignatureKeyPair)
            .addFunction("GetSignatureSize", &CScriptCryptoApi::GetSignatureSize)
            .addFunction("SignBuffer", &CScriptCryptoApi::SignBuffer)
            .addFunction("VerifyBuffer", &CScriptCryptoApi::VerifyBuffer)
            .addFunction("GenerateKeyAgreementKeyPair", &CScriptCryptoApi::GenerateKeyAgreementKeyPair)
            .addFunction("GetKeyAgreementPublicKeySize", &CScriptCryptoApi::GetKeyAgreementPublicKeySize)
            .addFunction("GetSharedSecretSize", &CScriptCryptoApi::GetSharedSecretSize)
            .addFunction("ExportKeyAgreementPublicKey", &CScriptCryptoApi::ExportKeyAgreementPublicKey)
            .addFunction("DeriveSharedSecret", &CScriptCryptoApi::DeriveSharedSecret)
            .addFunction("GenerateRandomBytes",
                static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const int)>(&CScriptCryptoApi::GenerateRandomBytes),
                static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const RandomAlgorithm, const int)>(&CScriptCryptoApi::GenerateRandomBytes))
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptPgpEngine>("PgpEngine")
            .addConstructor<
                void (*)(),
                void (*)(const int),
                void (*)(const PgpKeyAlgorithm)>()
            .addFunction("GetKeyAlgorithm", &CScriptPgpEngine::GetKeyAlgorithm)
            .addFunction("GenerateKeyPair",
                static_cast<void(CScriptPgpEngine::*)(const std::string&, const std::string&)>(&CScriptPgpEngine::GenerateKeyPair),
                static_cast<void(CScriptPgpEngine::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngine::GenerateKeyPair))
            .addFunction("GetKeyExpirationSeconds", &CScriptPgpEngine::GetKeyExpirationSeconds)
            .addFunction("ExportPublicKeyArmored", &CScriptPgpEngine::ExportPublicKeyArmored)
            .addFunction("ExportSecretKeyArmored", &CScriptPgpEngine::ExportSecretKeyArmored)
            .addFunction("GetKeyId", &CScriptPgpEngine::GetKeyId)
            .addFunction("RevokeKeyArmored", &CScriptPgpEngine::RevokeKeyArmored)
            .addFunction("ImportPeerPublicKey",
                static_cast<void(CScriptPgpEngine::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngine::ImportPeerPublicKey),
                static_cast<void(CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportPeerPublicKey))
            .addFunction("GetPeerKeyId", &CScriptPgpEngine::GetPeerKeyId)
            .addFunction("ImportAdditionalRecipientPublicKey",
                static_cast<void(CScriptPgpEngine::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngine::ImportAdditionalRecipientPublicKey),
                static_cast<void(CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportAdditionalRecipientPublicKey))
            .addFunction("EncryptBuffer", &CScriptPgpEngine::EncryptBuffer)
            .addFunction("EncryptStringArmored", &CScriptPgpEngine::EncryptStringArmored)
            .addFunction("DecryptBuffer", &CScriptPgpEngine::DecryptBuffer)
            .addFunction("DecryptStringArmored", &CScriptPgpEngine::DecryptStringArmored)
            .addFunction("SignBuffer", &CScriptPgpEngine::SignBuffer)
            .addFunction("VerifyBuffer", &CScriptPgpEngine::VerifyBuffer)
            .addFunction("ClearSignString", &CScriptPgpEngine::ClearSignString)
            .addFunction("VerifyClearSignedString", &CScriptPgpEngine::VerifyClearSignedString)
            .addFunction("EncryptFile", &CScriptPgpEngine::EncryptFile)
            .addFunction("EncryptFileCompressed", &CScriptPgpEngine::EncryptFileCompressed)
            .addFunction("DecryptFile", &CScriptPgpEngine::DecryptFile)
            .addFunction("SignFile", &CScriptPgpEngine::SignFile)
            .addFunction("VerifyFile", &CScriptPgpEngine::VerifyFile)
            .addFunction("IsPublicKeyEncrypted", &CScriptPgpEngine::IsPublicKeyEncrypted)
            .addFunction("IsPasswordEncrypted", &CScriptPgpEngine::IsPasswordEncrypted)
            .addFunction("IsIntegrityProtected", &CScriptPgpEngine::IsIntegrityProtected)
            .addFunction("GetCompression", &CScriptPgpEngine::GetCompression)
            .addFunction("ListEncryptionKeyIds", &CScriptPgpEngine::ListEncryptionKeyIds)
            .addFunction("ListSigningKeyIds", &CScriptPgpEngine::ListSigningKeyIds)
            .addFunction("ListSignatures", &CScriptPgpEngine::ListSignatures)
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptPgpEngineWrapper>("PgpEngineWrapper")
            .addConstructor<
                void (*)(),
                void (*)(const int)>()
            .addFunction("IsGnuPgAvailable", &CScriptPgpEngineWrapper::IsGnuPgAvailable)
            .addFunction("GenerateKeyPair",
                static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&)>(&CScriptPgpEngineWrapper::GenerateKeyPair),
                static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngineWrapper::GenerateKeyPair))
            .addFunction("GenerateKeyPairEcc",
                static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&)>(&CScriptPgpEngineWrapper::GenerateKeyPairEcc),
                static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngineWrapper::GenerateKeyPairEcc))
            .addFunction("GetKeyExpirationSeconds", &CScriptPgpEngineWrapper::GetKeyExpirationSeconds)
            .addFunction("ExportPublicKeyArmored", &CScriptPgpEngineWrapper::ExportPublicKeyArmored)
            .addFunction("ExportSecretKeyArmored", &CScriptPgpEngineWrapper::ExportSecretKeyArmored)
            .addFunction("GetKeyId", &CScriptPgpEngineWrapper::GetKeyId)
            .addFunction("RevokeKeyArmored", &CScriptPgpEngineWrapper::RevokeKeyArmored)
            .addFunction("ImportPeerPublicKey",
                static_cast<void(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngineWrapper::ImportPeerPublicKey),
                static_cast<void(CScriptPgpEngineWrapper::*)(const std::string&)>(&CScriptPgpEngineWrapper::ImportPeerPublicKey))
            .addFunction("GetPeerKeyId", &CScriptPgpEngineWrapper::GetPeerKeyId)
            .addFunction("GetImportedPeerKeyCount", &CScriptPgpEngineWrapper::GetImportedPeerKeyCount)
            .addFunction("GetImportedPeerKeyId", &CScriptPgpEngineWrapper::GetImportedPeerKeyId)
            .addFunction("GetKeyringListing", &CScriptPgpEngineWrapper::GetKeyringListing)
            .addFunction("GetKeyringKeyCount", &CScriptPgpEngineWrapper::GetKeyringKeyCount)
            .addFunction("GetKeyringKeyId", &CScriptPgpEngineWrapper::GetKeyringKeyId)
            .addFunction("DeletePeerPublicKey", &CScriptPgpEngineWrapper::DeletePeerPublicKey)
            .addFunction("DeleteOwnIdentity", &CScriptPgpEngineWrapper::DeleteOwnIdentity)
            .addFunction("EncryptBuffer",
                static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngineWrapper::EncryptBuffer),
                static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptBuffer))
            .addFunction("EncryptStringArmored",
                static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&)>(&CScriptPgpEngineWrapper::EncryptStringArmored),
                static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptStringArmored))
            .addFunction("EncryptBufferSymmetric", &CScriptPgpEngineWrapper::EncryptBufferSymmetric)
            .addFunction("EncryptStringArmoredSymmetric", &CScriptPgpEngineWrapper::EncryptStringArmoredSymmetric)
            .addFunction("EncryptBufferMultiRecipient",
                static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const std::vector<std::string>&)>(&CScriptPgpEngineWrapper::EncryptBufferMultiRecipient),
                static_cast<std::vector<unsigned char>(CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const std::vector<std::string>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptBufferMultiRecipient))
            .addFunction("EncryptStringArmoredMultiRecipient",
                static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const std::vector<std::string>&)>(&CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient),
                static_cast<std::string(CScriptPgpEngineWrapper::*)(const std::string&, const std::vector<std::string>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient))
            .addFunction("DecryptBuffer", &CScriptPgpEngineWrapper::DecryptBuffer)
            .addFunction("DecryptStringArmored", &CScriptPgpEngineWrapper::DecryptStringArmored)
            .addFunction("SignBuffer", &CScriptPgpEngineWrapper::SignBuffer)
            .addFunction("VerifyBuffer", &CScriptPgpEngineWrapper::VerifyBuffer)
            .addFunction("ClearSignString", &CScriptPgpEngineWrapper::ClearSignString)
            .addFunction("VerifyClearSignedString", &CScriptPgpEngineWrapper::VerifyClearSignedString)
            .addFunction("EncryptFile", &CScriptPgpEngineWrapper::EncryptFile)
            .addFunction("DecryptFile", &CScriptPgpEngineWrapper::DecryptFile)
            .addFunction("SignFile", &CScriptPgpEngineWrapper::SignFile)
            .addFunction("VerifyFile", &CScriptPgpEngineWrapper::VerifyFile)
            .addFunction("IsPublicKeyEncrypted", &CScriptPgpEngineWrapper::IsPublicKeyEncrypted)
            .addFunction("IsPasswordEncrypted", &CScriptPgpEngineWrapper::IsPasswordEncrypted)
            .addFunction("IsIntegrityProtected", &CScriptPgpEngineWrapper::IsIntegrityProtected)
            .addFunction("GetCompression", &CScriptPgpEngineWrapper::GetCompression)
            .addFunction("ListEncryptionKeyIds", &CScriptPgpEngineWrapper::ListEncryptionKeyIds)
            .addFunction("ListSigningKeyIds", &CScriptPgpEngineWrapper::ListSigningKeyIds)
            .addFunction("ListSignatures", &CScriptPgpEngineWrapper::ListSignatures)
        .endClass();
#endif // !DLL_RUNNER

    // DLL-hosted facades (CScriptCryptoApiDll/CScriptPgpEngineDll/CScriptPgpEngineWrapperDll) --
    // lightweight, no CCryptoApi/CPgpEngine/CPgpEngineWrapper dependency, so registered
    // unconditionally (harmless for AppBuilder, required for DllRunner). No constructor is
    // registered -- these are only ever pushed as an already-constructed instance via
    // SetDllCryptoApi/SetDllPgpEngine/SetDllPgpEngineWrapper below, never a script's own
    // constructor call.
    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptCryptoApiDll>("CryptoApiDll")
            .addFunction("GetVersion", &CScriptCryptoApiDll::GetVersion)
            .addFunction("GetHashSize", &CScriptCryptoApiDll::GetHashSize)
            .addFunction("ComputeHashString", &CScriptCryptoApiDll::ComputeHashString)
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptPgpEngineDll>("PgpEngineDll")
            .addFunction("GenerateKeyPair", &CScriptPgpEngineDll::GenerateKeyPair)
            .addFunction("ExportPublicKeyArmored", &CScriptPgpEngineDll::ExportPublicKeyArmored)
            .addFunction("ImportPeerPublicKey", &CScriptPgpEngineDll::ImportPeerPublicKey)
            .addFunction("EncryptStringArmored", &CScriptPgpEngineDll::EncryptStringArmored)
            .addFunction("DecryptStringArmored", &CScriptPgpEngineDll::DecryptStringArmored)
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptPgpEngineWrapperDll>("PgpEngineWrapperDll")
            .addFunction("IsGnuPgAvailable", &CScriptPgpEngineWrapperDll::IsGnuPgAvailable)
            .addFunction("GenerateKeyPair", &CScriptPgpEngineWrapperDll::GenerateKeyPair)
            .addFunction("ExportPublicKeyArmored", &CScriptPgpEngineWrapperDll::ExportPublicKeyArmored)
            .addFunction("ImportPeerPublicKey", &CScriptPgpEngineWrapperDll::ImportPeerPublicKey)
            .addFunction("EncryptStringArmored", &CScriptPgpEngineWrapperDll::EncryptStringArmored)
            .addFunction("DecryptStringArmored", &CScriptPgpEngineWrapperDll::DecryptStringArmored)
        .endClass();
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridge::SetDllCryptoApi(CScriptCryptoApiDll* api)
{
    try
    {
        luabridge::setGlobal(luaState_, api, "cryptoApi");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridge::SetDllPgpEngine(CScriptPgpEngineDll* engine)
{
    try
    {
        luabridge::setGlobal(luaState_, engine, "pgpEngine");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridge::SetDllPgpEngineWrapper(CScriptPgpEngineWrapperDll* wrapper)
{
    try
    {
        luabridge::setGlobal(luaState_, wrapper, "pgpEngineWrapper");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

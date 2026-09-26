#include "LuaScriptEngineLuaBridgeLegacy.h"
#include "../ScriptException.h"
#include "../ScriptCryptoApiDll.h"
#include "../ScriptPgpEngineDll.h"
#include "../ScriptPgpEngineWrapperDll.h"
#include "../ScriptCertificateManagerDll.h"
#include "../ScriptCmsServiceDll.h"
#include "../ScriptTimestampServiceDll.h"
#include "../ScriptProgressCallback.h"

// DLL_RUNNER (defined by DllRunner.vcxproj's PreprocessorDefinitions) skips every include/
// registration below that would otherwise pull in CCryptoApi/CPgpEngine/CPgpEngineWrapper's own
// concrete implementation -- see ScriptCryptoApiDll.h's own header comment for why DllRunner must
// never link that. Same technique CLuaScriptEngineSol.cpp's own guard already uses.
#ifndef DLL_RUNNER
#include "../ScriptCryptoApi.h"
#include "../ScriptPgpEngine.h"
#include "../ScriptPgpEngineWrapper.h"
#include "../ScriptCertificateManager.h"
#include "../ScriptCmsService.h"
#include "../ScriptTimestampService.h"

#include "Providers/ProviderTypes.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"
#include "Certificates/CertificateManager.h"
#include "Certificates/CmsService.h"
#include "Certificates/TimestampService.h"
#endif

#include "Definitions/Definitions.h"

extern "C"
{
#include <lauxlib.h>
#include <lualib.h>
}

// LuaScriptEngineLuaBridge.cpp (LuaBridge3) also declares a namespace called "luabridge" --
// completely different, incompatible classes (Namespace, Registrar, Stack<T>, etc.) under the same
// fully-qualified names. Linking both into the same executable without disambiguation violates the
// One Definition Rule: the linker silently keeps only one definition for both translation units, so
// whichever engine loses the coin flip runs its Lua-stack bookkeeping against code that was never
// designed for it. Observed directly: "Assertion failed: popsCount <= lua_gettop(L)" thrown from
// LuaBridge3's own Registrar destructor, firing well after every LuaBridge3 test had already
// reported PASSED, right as this engine's own registration ran elsewhere in the same process.
//
// Fix: rename THIS file's copy of the namespace via a preprocessor macro before including LuaBridge
// 2.10's headers -- every "luabridge" TOKEN in those headers (and in this file's own later use of
// "luabridge::...") textually becomes "luabridge_legacy", giving this translation unit's classes a
// distinct fully-qualified name with zero changes to the vendored source. Left defined for the rest
// of this file (never #undef'd) so registerBindings() below can keep writing plain "luabridge::...".
#define luabridge luabridge_legacy
#include <LuaBridge/LuaBridge.h>
#include <LuaBridge/Vector.h>

// C++-calls-INTO-script direction: LuaBridge 2.10 has no built-in Stack<std::function<Sig>>
// conversion either (same gap LuaScriptEngineLuaBridge.cpp's own identical specialization
// documents for LuaBridge3), so this converts a Lua function value into a
// CryptoApiNS::ScriptProgressCallback by hand. This version's own LuaRef::operator() (unlike
// LuaBridge3's TypeResult-returning one) throws a luabridge::LuaException on a Lua-side runtime
// error instead of returning an error code -- caught here and treated as "continue" (true), same
// reasoning as LuaScriptEngineLuaBridge.cpp's own specialization for why a script-side failure to
// produce a clean bool defaults to continuing rather than aborting.
//
// Deliberately NOT guarded by #ifndef DLL_RUNNER (unlike the block that used to wrap this):
// ScriptProgressCallback lives in the lightweight ScriptProgressCallback.h (no CCryptoApi/
// provider-stack dependency), so this specialization is needed -- and safe to compile -- under
// DLL_RUNNER too, for CScriptCryptoApiDll's own EncryptFileWithProgress/DecryptFileWithProgress
// registration further below.
namespace luabridge
{

template <> struct Stack<CryptoApiNS::ScriptProgressCallback>
{
    static void push(lua_State* L, const CryptoApiNS::ScriptProgressCallback&)
    {
        lua_pushnil(L);
    }

    static CryptoApiNS::ScriptProgressCallback get(lua_State* L, int index)
    {
        LuaRef ref(LuaRef::fromStack(L, index));
        return CryptoApiNS::ScriptProgressCallback(
            [ref](unsigned long long currentByte, unsigned long long totalByte, double percentage) -> bool
            {
                try
                {
                    LuaRef result = ref(currentByte, totalByte, percentage);
                    return result.cast<bool>();
                }
                catch (...)
                {
                    return true;
                }
            });
    }

    static bool isInstance(lua_State* L, int index)
    {
        return lua_isfunction(L, index) != 0;
    }
};

} // namespace luabridge

namespace CryptoApiNS
{

CLuaScriptEngineLuaBridgeLegacy::~CLuaScriptEngineLuaBridgeLegacy()
{
    lua_close(luaState_);
}
// -----------------------------------------------------------------------------

CLuaScriptEngineLuaBridgeLegacy::CLuaScriptEngineLuaBridgeLegacy() : luaState_(luaL_newstate())
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

void CLuaScriptEngineLuaBridgeLegacy::RunFile(const std::string& filePath)
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

void CLuaScriptEngineLuaBridgeLegacy::RunString(const std::string& code)
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

bool CLuaScriptEngineLuaBridgeLegacy::GetGlobalBool(const std::string& name) const
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

int CLuaScriptEngineLuaBridgeLegacy::GetGlobalInt(const std::string& name) const
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

std::string CLuaScriptEngineLuaBridgeLegacy::GetGlobalString(const std::string& name) const
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

void CLuaScriptEngineLuaBridgeLegacy::registerBindings(void)
{
#ifndef DLL_RUNNER
    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptCryptoApi>("CryptoApi")
            .addConstructor<void (*)()>()
            .addFunction("GetVersion", &CScriptCryptoApi::GetVersion)
            .addFunction("EncryptString", &CScriptCryptoApi::EncryptString)
            .addFunction("DecryptString", &CScriptCryptoApi::DecryptString)
            .addFunction("GenerateAsymmetricKeyPair", &CScriptCryptoApi::GenerateAsymmetricKeyPair)
            .addFunction("GetAsymmetricCiphertextSize", &CScriptCryptoApi::GetAsymmetricCiphertextSize)
            .addFunction("EncryptWithPublicKey", &CScriptCryptoApi::EncryptWithPublicKey)
            .addFunction("DecryptWithPrivateKey", &CScriptCryptoApi::DecryptWithPrivateKey)
            .addFunction("GetHashSize", &CScriptCryptoApi::GetHashSize)
            .addFunction("ComputeHashString", &CScriptCryptoApi::ComputeHashString)
            .addFunction("EncryptFile",
                static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&)>(&CScriptCryptoApi::EncryptFile))
            .addFunction("DecryptFile",
                static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&)>(&CScriptCryptoApi::DecryptFile))
            // C++-calls-INTO-script direction: see the Stack<CryptoApiNS::ScriptProgressCallback>
            // specialization above this class's registerBindings() for the hand-written Lua
            // function -> std::function conversion this relies on.
            .addFunction("EncryptFileWithProgress",
                static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&, const CryptoApiNS::ScriptProgressCallback&)>(&CScriptCryptoApi::EncryptFile))
            .addFunction("DecryptFileWithProgress",
                static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&, const CryptoApiNS::ScriptProgressCallback&)>(&CScriptCryptoApi::DecryptFile))
            .addFunction("GenerateSignatureKeyPair", &CScriptCryptoApi::GenerateSignatureKeyPair)
            .addFunction("GetSignatureSize", &CScriptCryptoApi::GetSignatureSize)
            .addFunction("SignBuffer", &CScriptCryptoApi::SignBuffer)
            .addFunction("VerifyBuffer", &CScriptCryptoApi::VerifyBuffer)
            .addFunction("GenerateKeyAgreementKeyPair", &CScriptCryptoApi::GenerateKeyAgreementKeyPair)
            .addFunction("GetSharedSecretSize", &CScriptCryptoApi::GetSharedSecretSize)
            .addFunction("ExportKeyAgreementPublicKey", &CScriptCryptoApi::ExportKeyAgreementPublicKey)
            .addFunction("DeriveSharedSecret", &CScriptCryptoApi::DeriveSharedSecret)
            .addFunction("GenerateRandomBytes",
                static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const int)>(&CScriptCryptoApi::GenerateRandomBytes))
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptPgpEngine>("PgpEngine")
            .addConstructor<void (*)()>()
            .addFunction("GenerateKeyPair",
                static_cast<void(CScriptPgpEngine::*)(const std::string&, const std::string&)>(&CScriptPgpEngine::GenerateKeyPair))
            .addFunction("GetKeyId", &CScriptPgpEngine::GetKeyId)
            .addFunction("ExportPublicKeyArmored", &CScriptPgpEngine::ExportPublicKeyArmored)
            .addFunction("ImportPeerPublicKey",
                static_cast<void(CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportPeerPublicKey))
            .addFunction("EncryptStringArmored", &CScriptPgpEngine::EncryptStringArmored)
            .addFunction("DecryptStringArmored", &CScriptPgpEngine::DecryptStringArmored)
            .addFunction("ClearSignString", &CScriptPgpEngine::ClearSignString)
            .addFunction("VerifyClearSignedString", &CScriptPgpEngine::VerifyClearSignedString)
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptPgpEngineWrapper>("PgpEngineWrapper")
            .addConstructor<void (*)()>()
            .addFunction("IsGnuPgAvailable", &CScriptPgpEngineWrapper::IsGnuPgAvailable)
        .endClass();

    // None of CScriptCertificateManager/CScriptCmsService/CScriptTimestampService have overloaded
    // methods or enum-typed parameters (see CScriptCertificateManager.h's own header comment for
    // why algorithm/mode parameters are plain int), so LuaBridge 2.10's single-signature
    // addConstructor/addFunction limitation (see this file's own header comment) does not force a
    // reduced surface here the way CScriptPgpEngine/CScriptPgpEngineWrapper's overloads did above --
    // every method registers directly, no static_cast disambiguation needed.
    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptCertificateManager>("CertificateManager")
            .addConstructor<void (*)()>()
            .addFunction("GetCertificateInfoText", &CScriptCertificateManager::GetCertificateInfoText)
            .addFunction("ConvertCertificateDerToPem", &CScriptCertificateManager::ConvertCertificateDerToPem)
            .addFunction("ConvertCertificatePemToDer", &CScriptCertificateManager::ConvertCertificatePemToDer)
            .addFunction("CreateSelfSignedCertificate", &CScriptCertificateManager::CreateSelfSignedCertificate)
            .addFunction("CreateCertificateRequest", &CScriptCertificateManager::CreateCertificateRequest)
            .addFunction("GetLastPrivateKeyPem", &CScriptCertificateManager::GetLastPrivateKeyPem)
            .addFunction("IssueCertificateFromRequest", &CScriptCertificateManager::IssueCertificateFromRequest)
            .addFunction("AddIntermediateCertificateForChainValidation", &CScriptCertificateManager::AddIntermediateCertificateForChainValidation)
            .addFunction("ClearIntermediateCertificatesForChainValidation", &CScriptCertificateManager::ClearIntermediateCertificatesForChainValidation)
            .addFunction("ValidateChain", &CScriptCertificateManager::ValidateChain)
            .addFunction("GetLastRevocationStatus", &CScriptCertificateManager::GetLastRevocationStatus)
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptCmsService>("CmsService")
            .addConstructor<void (*)()>()
            .addFunction("SignDetached", &CScriptCmsService::SignDetached)
            .addFunction("VerifyDetached", &CScriptCmsService::VerifyDetached)
            .addFunction("ExtractSignerCertificate", &CScriptCmsService::ExtractSignerCertificate)
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptTimestampService>("TimestampService")
            .addConstructor<void (*)()>()
            .addFunction("CreateTimestampRequest", &CScriptTimestampService::CreateTimestampRequest)
            .addFunction("RequestTimestampFromTsa", &CScriptTimestampService::RequestTimestampFromTsa)
            .addFunction("VerifyTimestampResponse", &CScriptTimestampService::VerifyTimestampResponse)
            .addFunction("GetTimestampInfoText", &CScriptTimestampService::GetTimestampInfoText)
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
            .addFunction("EncryptFileWithProgress", &CScriptCryptoApiDll::EncryptFile)
            .addFunction("DecryptFileWithProgress", &CScriptCryptoApiDll::DecryptFile)
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

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptCertificateManagerDll>("CertificateManagerDll")
            .addFunction("CreateSelfSignedCertificate", &CScriptCertificateManagerDll::CreateSelfSignedCertificate)
            .addFunction("GetLastPrivateKeyPem", &CScriptCertificateManagerDll::GetLastPrivateKeyPem)
            .addFunction("GetCertificateInfoText", &CScriptCertificateManagerDll::GetCertificateInfoText)
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptCmsServiceDll>("CmsServiceDll")
            .addFunction("SignDetached", &CScriptCmsServiceDll::SignDetached)
            .addFunction("VerifyDetached", &CScriptCmsServiceDll::VerifyDetached)
        .endClass();

    luabridge::getGlobalNamespace(luaState_)
        .beginClass<CScriptTimestampServiceDll>("TimestampServiceDll")
            .addFunction("CreateTimestampRequest", &CScriptTimestampServiceDll::CreateTimestampRequest)
            .addFunction("RequestTimestampFromTsa", &CScriptTimestampServiceDll::RequestTimestampFromTsa)
            .addFunction("GetTimestampInfoText", &CScriptTimestampServiceDll::GetTimestampInfoText)
        .endClass();
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridgeLegacy::SetDllCryptoApi(CScriptCryptoApiDll* api)
{
    try
    {
        luabridge::push(luaState_, api);
        lua_setglobal(luaState_, "cryptoApi");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridgeLegacy::SetDllPgpEngine(CScriptPgpEngineDll* engine)
{
    try
    {
        luabridge::push(luaState_, engine);
        lua_setglobal(luaState_, "pgpEngine");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridgeLegacy::SetDllPgpEngineWrapper(CScriptPgpEngineWrapperDll* wrapper)
{
    try
    {
        luabridge::push(luaState_, wrapper);
        lua_setglobal(luaState_, "pgpEngineWrapper");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridgeLegacy::SetDllCertificateManager(CScriptCertificateManagerDll* manager)
{
    try
    {
        luabridge::push(luaState_, manager);
        lua_setglobal(luaState_, "certificateManager");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridgeLegacy::SetDllCmsService(CScriptCmsServiceDll* service)
{
    try
    {
        luabridge::push(luaState_, service);
        lua_setglobal(luaState_, "cmsService");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CLuaScriptEngineLuaBridgeLegacy::SetDllTimestampService(CScriptTimestampServiceDll* service)
{
    try
    {
        luabridge::push(luaState_, service);
        lua_setglobal(luaState_, "timestampService");
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

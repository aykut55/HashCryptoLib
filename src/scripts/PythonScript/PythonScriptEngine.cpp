// Definitions.h (ErrorCode's enum { NO_ERROR = 0, ... }) MUST be the first thing this translation
// unit parses -- exact same reasoning as ChaiScriptEngine.cpp's own top-of-file comment: pybind11's
// embed.h transitively includes <Windows.h> (Python.h itself pulls Windows headers on _WIN32), and
// WinError.h's own "#define NO_ERROR 0L" then textually replaces the enum's first member wherever it
// appears afterward -- INCLUDING at the enum's own declaration site if Definitions.h is parsed only
// later, turning "enum ErrorCode { NO_ERROR = 0" into the syntactically invalid "enum ErrorCode { 0L
// = 0" and cascading into every other member being reported "undeclared". Parsing Definitions.h here,
// before anything below ever gets a chance to define that macro, avoids the whole problem.
#include "Definitions/Definitions.h"

#include "PythonScriptEngine.h"

// The vendored CPython embed (3rdParty\scripts\python312, see 3rdParty/PYTHON_EMBED.md) is x64 ONLY:
// python.org's Windows embeddable package ships amd64 binaries only, no Win32/x86 build. Rules.md
// guarantees ARCH_X64/ARCH_WIN64 (x64) and ARCH_X86/ARCH_WIN32 (Win32) are defined by every
// projects/msvc project, so those are the primary switch; _WIN64 is only a fallback for a build that
// defines neither (e.g. a standalone compile outside this repo's own project files). When this is 0,
// NOT ONE pybind11/Python header is compiled in, and every method below reports the same honest-
// unsupported behaviour LibgcryptProvider.cpp already established for its own x64-only gap (throwing
// CScriptException for the two methods that have no other way to report "this build has no Python
// support", and false/0/empty string for GetGlobalBool/Int/String, matching their own already-
// established "return a safe default on any failure" convention).
#if defined(ARCH_X64) || defined(ARCH_WIN64)
#define CRYPTOAPI_PYTHON_AVAILABLE 1
#elif defined(ARCH_X86) || defined(ARCH_WIN32)
#define CRYPTOAPI_PYTHON_AVAILABLE 0
#elif defined(_WIN64)
#define CRYPTOAPI_PYTHON_AVAILABLE 1
#else
#define CRYPTOAPI_PYTHON_AVAILABLE 0
#endif

#if CRYPTOAPI_PYTHON_AVAILABLE

// pybind11 embedding's well-known Debug-build ABI gotcha: python.org's Windows embeddable package
// ships Release-only binaries (no python312_d.dll / python312_d.lib); pybind11/embed.h checks the
// _DEBUG macro and, if it is defined, tries to link against the debug-suffixed import library, which
// does not exist anywhere in our vendored set (Debug|x64 links the exact same python312.lib as
// Release|x64). This is pybind11's own documented workaround: temporarily #undef _DEBUG before
// #include <pybind11/embed.h>, then restore it immediately after -- guarded, so this only restores
// what was actually there (a Release build never had _DEBUG defined in the first place).
#ifdef _DEBUG
#define CRYPTOAPI_PYTHON_RESTORE_DEBUG 1
#undef _DEBUG
#else
#define CRYPTOAPI_PYTHON_RESTORE_DEBUG 0
#endif

#include <pybind11/embed.h>
#include <pybind11/eval.h>
#include <pybind11/stl.h>
// C++-calls-INTO-script direction: pybind11/functional.h's generic function_caster converts a
// Python callable into a std::function<Sig> automatically whenever a bound C++ parameter has that
// exact type (no custom conversion needed, same as ChaiScript's own automatic behavior) --
// EncryptFileWithProgress/DecryptFileWithProgress below rely on it.
#include <pybind11/functional.h>

#if CRYPTOAPI_PYTHON_RESTORE_DEBUG
#define _DEBUG 1
#endif
#undef CRYPTOAPI_PYTHON_RESTORE_DEBUG

namespace py = pybind11;

// <Windows.h> included explicitly here, BEFORE the NO_ERROR/EncryptFile/DecryptFile #undef block
// below -- GetModuleFileNameW/MAX_PATH (used later in this file, in getExecutableDirectory()) need
// it, and it MUST be pulled in before that #undef block runs, not after: pybind11/embed.h's own
// transitive Windows.h inclusion (via Python.h on _WIN32) does not necessarily define every macro
// this file cares about the same way a full, direct <Windows.h> include does, and a LATER #include
// <Windows.h> anywhere below this point would be a silent no-op (include guards) that leaves NO_ERROR/
// EncryptFile/DecryptFile undefined right up until this exact line -- so putting it after the #undef
// block, as an earlier version of this file did, let those macros come back from nowhere partway
// through the file and corrupt everything parsed afterward (the py::enum_<ErrorCode>::value() call,
// and the EncryptFile/DecryptFile facade method references, further down). Verified the hard way
// while building this engine the first time.
#include <Windows.h>

// pybind11/embed.h's own <Windows.h> (pulled in transitively through Python.h) leaves two macros
// defined for the rest of this translation unit -- and critically, that includes every header below
// this point, not just this file's own later code:
//   - NO_ERROR (WinError.h, "#define NO_ERROR 0L") -- see the comment at the top of this file for why
//     parsing Definitions.h first (before any pybind11/Python header) keeps the enum DECLARATION
//     itself safe; this second #undef protects every later bare "NO_ERROR" token (e.g. inside
//     registerBindings() below) from silently becoming the literal 0L instead of the real
//     CryptoApiNS::ErrorCode enumerator. Same precedent as ChaiScriptEngine.cpp/CryptoApiDllLoader.h.
//   - EncryptFile/DecryptFile (winbase.h, real Win32 APIs, macro-aliased to their *W Unicode overload
//     under this project's UNICODE charset) -- MUST be undone before the facade headers below are
//     parsed: CScriptCryptoApi/CScriptPgpEngine/CScriptPgpEngineWrapper each declare a method
//     literally named EncryptFile/DecryptFile, and the preprocessor does not care that those are
//     class member declarations -- it macro-substitutes the token everywhere, silently renaming the
//     declared members themselves to EncryptFileW/DecryptFileW if this isn't undone first. Same
//     precedent as ChaiScriptEngine.cpp/CryptoApi.cpp's own #undef of both.
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
#include "../ScriptCertificateManagerDll.h"
#include "../ScriptCmsServiceDll.h"
#include "../ScriptTimestampServiceDll.h"

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

#include <atomic>
#include <string>
#include <vector>

namespace CryptoApiNS
{

namespace
{
    // Py_Initialize/Py_Finalize is PROCESS-WIDE state, not per-C++-object (unlike ChaiScript's own
    // chaiscript::ChaiScript, which is a genuinely independent interpreter per instance) --
    // CScriptEngineTester constructs a fresh CPythonScriptEngine per test method, so this tracks how
    // many CPythonScriptEngine instances are currently alive in THIS process and only actually calls
    // py::initialize_interpreter()/py::finalize_interpreter() on the 0->1 / 1->0 transition. A plain
    // int would be enough for this repo's actual usage (always single-threaded, sequential
    // construction/destruction from Main.cpp's own test-running functions), but std::atomic costs
    // nothing here and removes any doubt if that ever changes.
    std::atomic<int> g_pythonInterpreterRefCount(0);

    // GetModuleFileNameW(nullptr, ...) reports the currently running executable's own path -- this
    // is deliberately NOT the source-tree vendored path (3rdParty\scripts\python312\bin), which will
    // not exist wherever AppBuilder.exe eventually gets deployed/copied to. AppBuilder.vcxproj's own
    // PostBuildEvent (see the x64-only ItemDefinitionGroup for CPythonScriptEngine) copies
    // python312.dll/*.pyd/python312.zip next to the built executable itself, so pointing the
    // interpreter's module search path at the executable's own directory is what actually finds them
    // at runtime, in a real build output directory as much as in a hypothetical deployed one.
    std::wstring getExecutableDirectory(void)
    {
        wchar_t buffer[MAX_PATH];
        DWORD length = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
        if (length == 0 || length >= MAX_PATH)
        {
            return std::wstring();
        }

        std::wstring path(buffer, length);
        std::wstring::size_type lastSlash = path.find_last_of(L"\\/");
        if (lastSlash == std::wstring::npos)
        {
            return std::wstring();
        }

        return path.substr(0, lastSlash);
    }
} // unnamed namespace

// PYBIND11_EMBEDDED_MODULE expands to an extern "C" PyInit_cryptoapi_native() function definition;
// extern "C" linkage is never name-mangled by an enclosing C++ namespace (that is the whole point of
// extern "C"), so defining it here, directly inside namespace CryptoApiNS (but deliberately OUTSIDE
// the anonymous namespace above -- pybind11's own docs call for "global scope", and an anonymous
// namespace's internal-linkage machinery is the one part of that guidance worth actually respecting)
// is both safe for the CPython import machinery AND lets every enum/class below resolve by its
// plain, unqualified CryptoApiNS name (ErrorCode, ProviderKind, CScriptCryptoApi, ...) exactly like
// the rest of this file already does.
//
// PYBIND11_EMBEDDED_MODULE registers this module's init function with CPython's own inittab ONCE
// per process (a static registration, independent of how many times the interpreter itself is
// subsequently initialized/finalized) -- every fresh py::initialize_interpreter() call re-runs the
// body below from scratch against that fresh interpreter's own state, which is exactly the
// documented, supported pybind11 pattern for repeated embedding lifetimes (see embed.h's own "the
// interpreter can be restarted by calling initialize_interpreter again" note). Scripts never import
// "cryptoapi_native" explicitly -- CPythonScriptEngine::registerBindings() does "from
// cryptoapi_native import *" once per engine instance so every class/constant is directly visible by
// its bare name, matching how Lua/LuaBridge/ChaiScript scripts never need an import/require either.
//
// std::vector<unsigned char> (every ...Buffer()/...Bytes() facade parameter/return type) crosses
// into Python as a plain `list` of ints via pybind11/stl.h's generic list_caster -- len()/indexing/
// equality all work on it directly from a script with zero extra registration, unlike ChaiScript's
// own ByteVector, which needed an explicit
// chaiscript::bootstrap::standard_library::vector_type<...> registration for the same thing.
// ToBytes()/ToStringFromBytes() below are still provided, purely for script-author convenience
// building a byte buffer out of a Python str (mirroring ChaiScript's identically-named helpers) --
// not because pybind11 needs them to make std::vector<unsigned char> itself work.
PYBIND11_EMBEDDED_MODULE(cryptoapi_native, m)
{
        m.def("ToBytes", [](const std::string& text)
        {
            return std::vector<unsigned char>(text.begin(), text.end());
        });

        m.def("ToStringFromBytes", [](const std::vector<unsigned char>& bytes)
        {
            return std::string(bytes.begin(), bytes.end());
        });

        py::enum_<ErrorCode>(m, "ErrorCode")
            .value("NO_ERROR", NO_ERROR)
            .value("NOT_IMPLEMENTED", NOT_IMPLEMENTED)
            .value("UNEXPECTED_ERROR", UNEXPECTED_ERROR)
            .value("BUFFER_TOO_SMALL", BUFFER_TOO_SMALL)
            .value("INVALID_ARGUMENT", INVALID_ARGUMENT)
            .value("FILE_IO_ERROR", FILE_IO_ERROR)
            .value("INVALID_DATA", INVALID_DATA)
            .value("OPERATION_CANCELLED", OPERATION_CANCELLED)
            .export_values();

#ifndef DLL_RUNNER
        py::enum_<ProviderKind>(m, "ProviderKind")
            .value("PROVIDER_MICROSOFT", PROVIDER_MICROSOFT)
            .value("PROVIDER_CRYPTOPP", PROVIDER_CRYPTOPP)
            .value("PROVIDER_BOTAN", PROVIDER_BOTAN)
            .value("PROVIDER_OPENSSL", PROVIDER_OPENSSL)
            .value("PROVIDER_LIBGCRYPT", PROVIDER_LIBGCRYPT)
            .export_values();

        py::enum_<AeadAlgorithm>(m, "AeadAlgorithm")
            .value("AEAD_AES_128_GCM", AEAD_AES_128_GCM)
            .value("AEAD_AES_192_GCM", AEAD_AES_192_GCM)
            .value("AEAD_AES_256_GCM", AEAD_AES_256_GCM)
            .value("AEAD_AES_128_CCM", AEAD_AES_128_CCM)
            .value("AEAD_AES_192_CCM", AEAD_AES_192_CCM)
            .value("AEAD_AES_256_CCM", AEAD_AES_256_CCM)
            .value("AEAD_AES_128_EAX", AEAD_AES_128_EAX)
            .value("AEAD_AES_192_EAX", AEAD_AES_192_EAX)
            .value("AEAD_AES_256_EAX", AEAD_AES_256_EAX)
            .value("AEAD_AES_128_SIV", AEAD_AES_128_SIV)
            .value("AEAD_AES_256_SIV", AEAD_AES_256_SIV)
            .value("AEAD_AES_128_GCM_SIV", AEAD_AES_128_GCM_SIV)
            .value("AEAD_AES_256_GCM_SIV", AEAD_AES_256_GCM_SIV)
            .value("AEAD_CHACHA20_POLY1305", AEAD_CHACHA20_POLY1305)
            .value("AEAD_TWOFISH_GCM", AEAD_TWOFISH_GCM)
            .value("AEAD_SERPENT_GCM", AEAD_SERPENT_GCM)
            .value("AEAD_CAMELLIA_GCM", AEAD_CAMELLIA_GCM)
            .export_values();

        py::enum_<LegacySymmetricAlgorithm>(m, "LegacySymmetricAlgorithm")
            .value("LEGACY_AES_128_CBC", LEGACY_AES_128_CBC)
            .value("LEGACY_AES_192_CBC", LEGACY_AES_192_CBC)
            .value("LEGACY_AES_256_CBC", LEGACY_AES_256_CBC)
            .value("LEGACY_AES_128_CTR", LEGACY_AES_128_CTR)
            .value("LEGACY_AES_192_CTR", LEGACY_AES_192_CTR)
            .value("LEGACY_AES_256_CTR", LEGACY_AES_256_CTR)
            .value("LEGACY_AES_128_CFB", LEGACY_AES_128_CFB)
            .value("LEGACY_AES_192_CFB", LEGACY_AES_192_CFB)
            .value("LEGACY_AES_256_CFB", LEGACY_AES_256_CFB)
            .value("LEGACY_AES_128_OFB", LEGACY_AES_128_OFB)
            .value("LEGACY_AES_192_OFB", LEGACY_AES_192_OFB)
            .value("LEGACY_AES_256_OFB", LEGACY_AES_256_OFB)
            .value("LEGACY_AES_128_ECB", LEGACY_AES_128_ECB)
            .value("LEGACY_AES_192_ECB", LEGACY_AES_192_ECB)
            .value("LEGACY_AES_256_ECB", LEGACY_AES_256_ECB)
            .value("LEGACY_RC2_CBC", LEGACY_RC2_CBC)
            .value("LEGACY_RC2_ECB", LEGACY_RC2_ECB)
            .value("LEGACY_DES_CBC", LEGACY_DES_CBC)
            .value("LEGACY_DES_ECB", LEGACY_DES_ECB)
            .value("LEGACY_3DES_CBC", LEGACY_3DES_CBC)
            .value("LEGACY_3DES_ECB", LEGACY_3DES_ECB)
            .value("LEGACY_RC4", LEGACY_RC4)
            .export_values();

        py::enum_<AsymmetricAlgorithm>(m, "AsymmetricAlgorithm")
            .value("ASYMMETRIC_RSA_1024", ASYMMETRIC_RSA_1024)
            .value("ASYMMETRIC_RSA_2048", ASYMMETRIC_RSA_2048)
            .value("ASYMMETRIC_RSA_3072", ASYMMETRIC_RSA_3072)
            .value("ASYMMETRIC_RSA_4096", ASYMMETRIC_RSA_4096)
            .export_values();

        py::enum_<HashAlgorithm>(m, "HashAlgorithm")
            .value("HASH_MD5", HASH_MD5)
            .value("HASH_SHA1", HASH_SHA1)
            .value("HASH_SHA224", HASH_SHA224)
            .value("HASH_SHA256", HASH_SHA256)
            .value("HASH_SHA384", HASH_SHA384)
            .value("HASH_SHA512", HASH_SHA512)
            .value("HASH_SHA512_256", HASH_SHA512_256)
            .value("HASH_SHA3_224", HASH_SHA3_224)
            .value("HASH_SHA3_256", HASH_SHA3_256)
            .value("HASH_SHA3_384", HASH_SHA3_384)
            .value("HASH_SHA3_512", HASH_SHA3_512)
            .value("HASH_BLAKE2B", HASH_BLAKE2B)
            .value("HASH_BLAKE2S", HASH_BLAKE2S)
            .value("HASH_RIPEMD160", HASH_RIPEMD160)
            .export_values();

        py::enum_<SignatureAlgorithm>(m, "SignatureAlgorithm")
            .value("SIGNATURE_RSA_PSS_SHA256_2048", SIGNATURE_RSA_PSS_SHA256_2048)
            .value("SIGNATURE_RSA_PSS_SHA256_3072", SIGNATURE_RSA_PSS_SHA256_3072)
            .value("SIGNATURE_RSA_PSS_SHA256_4096", SIGNATURE_RSA_PSS_SHA256_4096)
            .value("SIGNATURE_ECDSA_P256_SHA256", SIGNATURE_ECDSA_P256_SHA256)
            .value("SIGNATURE_ED25519", SIGNATURE_ED25519)
            .value("SIGNATURE_ECDSA_P384_SHA384", SIGNATURE_ECDSA_P384_SHA384)
            .value("SIGNATURE_ECDSA_P521_SHA512", SIGNATURE_ECDSA_P521_SHA512)
            .value("SIGNATURE_DSA_SHA256_2048", SIGNATURE_DSA_SHA256_2048)
            .value("SIGNATURE_DSA_SHA256_3072", SIGNATURE_DSA_SHA256_3072)
            .export_values();

        py::enum_<KeyAgreementAlgorithm>(m, "KeyAgreementAlgorithm")
            .value("KEYAGREEMENT_ECDH_P256", KEYAGREEMENT_ECDH_P256)
            .value("KEYAGREEMENT_X25519", KEYAGREEMENT_X25519)
            .export_values();

        py::enum_<RandomAlgorithm>(m, "RandomAlgorithm")
            .value("RANDOM_SYSTEM", RANDOM_SYSTEM)
            .value("RANDOM_HASH_DRBG", RANDOM_HASH_DRBG)
            .value("RANDOM_HMAC_DRBG", RANDOM_HMAC_DRBG)
            .value("RANDOM_CTR_DRBG", RANDOM_CTR_DRBG)
            .export_values();

        py::enum_<PgpKeyAlgorithm>(m, "PgpKeyAlgorithm")
            .value("PGP_KEY_ALGORITHM_RSA", PGP_KEY_ALGORITHM_RSA)
            .value("PGP_KEY_ALGORITHM_ED25519_X25519", PGP_KEY_ALGORITHM_ED25519_X25519)
            .export_values();

        // Deliberately two distinct enum types/constant sets, never merged -- PgpFileCompressionAlgorithm
        // (CPgpEngine) and PgpCompressionAlgorithm (CPgpEngineWrapper) share the same namespace but have
        // different values for the same names (see PgpEngine.h/PgpEngineWrapper.h's own comments).
        py::enum_<PgpFileCompressionAlgorithm>(m, "PgpFileCompressionAlgorithm")
            .value("PGP_FILE_COMPRESSION_ALGORITHM_ZIP", PGP_FILE_COMPRESSION_ALGORITHM_ZIP)
            .value("PGP_FILE_COMPRESSION_ALGORITHM_ZLIB", PGP_FILE_COMPRESSION_ALGORITHM_ZLIB)
            .export_values();

        py::enum_<PgpCompressionAlgorithm>(m, "PgpCompressionAlgorithm")
            .value("PGP_COMPRESSION_ALGORITHM_NONE", PGP_COMPRESSION_ALGORITHM_NONE)
            .value("PGP_COMPRESSION_ALGORITHM_ZIP", PGP_COMPRESSION_ALGORITHM_ZIP)
            .value("PGP_COMPRESSION_ALGORITHM_ZLIB", PGP_COMPRESSION_ALGORITHM_ZLIB)
            .value("PGP_COMPRESSION_ALGORITHM_BZIP2", PGP_COMPRESSION_ALGORITHM_BZIP2)
            .export_values();

        py::enum_<PgpCompressionInspectionResult>(m, "PgpCompressionInspectionResult")
            .value("PGP_COMPRESSION_NOT_PRESENT", PGP_COMPRESSION_NOT_PRESENT)
            .value("PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION", PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION)
            .export_values();

        py::enum_<PgpInspectionRecordSize>(m, "PgpInspectionRecordSize")
            .value("PGP_INSPECTION_KEY_ID_RECORD_SIZE", PGP_INSPECTION_KEY_ID_RECORD_SIZE)
            .value("PGP_INSPECTION_SIGNATURE_RECORD_SIZE", PGP_INSPECTION_SIGNATURE_RECORD_SIZE)
            .export_values();

        py::class_<CScriptCryptoApi>(m, "CryptoApi")
            .def(py::init<>())
            .def(py::init<const ProviderKind, const AeadAlgorithm>())
            .def(py::init<const ProviderKind, const HashAlgorithm>())
            .def(py::init<const ProviderKind, const AsymmetricAlgorithm>())
            .def(py::init<const ProviderKind, const LegacySymmetricAlgorithm>())
            .def(py::init<const ProviderKind, const SignatureAlgorithm>())
            .def(py::init<const ProviderKind, const KeyAgreementAlgorithm>())
            .def(py::init<const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm>())
            .def(py::init<const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm>())
            .def(py::init<const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm>())
            .def(py::init<const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm, const SignatureAlgorithm>())
            .def(py::init<const ProviderKind, const AeadAlgorithm, const AsymmetricAlgorithm, const LegacySymmetricAlgorithm, const HashAlgorithm, const SignatureAlgorithm, const KeyAgreementAlgorithm>())
            .def("GetVersion", &CScriptCryptoApi::GetVersion)
            .def("EncryptBuffer", &CScriptCryptoApi::EncryptBuffer)
            .def("DecryptBuffer", &CScriptCryptoApi::DecryptBuffer)
            .def("EncryptBytes", &CScriptCryptoApi::EncryptBytes)
            .def("DecryptBytes", &CScriptCryptoApi::DecryptBytes)
            .def("EncryptString", &CScriptCryptoApi::EncryptString)
            .def("DecryptString", &CScriptCryptoApi::DecryptString)
            .def("EncryptFile", static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&)>(&CScriptCryptoApi::EncryptFile))
            .def("DecryptFile", static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&)>(&CScriptCryptoApi::DecryptFile))
            // C++-calls-INTO-script direction: pybind11/functional.h (included above) converts a
            // Python callable into a std::function<Sig> automatically whenever a bound overload's
            // parameter has that exact type -- called once per chunk from inside EncryptFile/
            // DecryptFile's own C++ loop.
            .def("EncryptFileWithProgress", static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&, const CryptoApiNS::ScriptProgressCallback&)>(&CScriptCryptoApi::EncryptFile))
            .def("DecryptFileWithProgress", static_cast<void(CScriptCryptoApi::*)(const std::string&, const std::string&, const std::string&, const CryptoApiNS::ScriptProgressCallback&)>(&CScriptCryptoApi::DecryptFile))
            .def("GenerateAsymmetricKeyPair", &CScriptCryptoApi::GenerateAsymmetricKeyPair)
            .def("GetMaxAsymmetricPlaintextSize", &CScriptCryptoApi::GetMaxAsymmetricPlaintextSize)
            .def("GetAsymmetricCiphertextSize", &CScriptCryptoApi::GetAsymmetricCiphertextSize)
            .def("EncryptWithPublicKey", &CScriptCryptoApi::EncryptWithPublicKey)
            .def("DecryptWithPrivateKey", &CScriptCryptoApi::DecryptWithPrivateKey)
            .def("EncryptLegacyBuffer", &CScriptCryptoApi::EncryptLegacyBuffer)
            .def("DecryptLegacyBuffer", &CScriptCryptoApi::DecryptLegacyBuffer)
            .def("GetHashSize", &CScriptCryptoApi::GetHashSize)
            .def("ComputeHashBuffer", &CScriptCryptoApi::ComputeHashBuffer)
            .def("ComputeHashBytes", &CScriptCryptoApi::ComputeHashBytes)
            .def("ComputeHashString", &CScriptCryptoApi::ComputeHashString)
            .def("ComputeHashFile", &CScriptCryptoApi::ComputeHashFile)
            .def("GenerateSignatureKeyPair", &CScriptCryptoApi::GenerateSignatureKeyPair)
            .def("GetSignatureSize", &CScriptCryptoApi::GetSignatureSize)
            .def("SignBuffer", &CScriptCryptoApi::SignBuffer)
            .def("VerifyBuffer", &CScriptCryptoApi::VerifyBuffer)
            .def("GenerateKeyAgreementKeyPair", &CScriptCryptoApi::GenerateKeyAgreementKeyPair)
            .def("GetKeyAgreementPublicKeySize", &CScriptCryptoApi::GetKeyAgreementPublicKeySize)
            .def("GetSharedSecretSize", &CScriptCryptoApi::GetSharedSecretSize)
            .def("ExportKeyAgreementPublicKey", &CScriptCryptoApi::ExportKeyAgreementPublicKey)
            .def("DeriveSharedSecret", &CScriptCryptoApi::DeriveSharedSecret)
            .def("GenerateRandomBytes", static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const int)>(&CScriptCryptoApi::GenerateRandomBytes))
            .def("GenerateRandomBytes", static_cast<std::vector<unsigned char>(CScriptCryptoApi::*)(const RandomAlgorithm, const int)>(&CScriptCryptoApi::GenerateRandomBytes))
            ;

        py::class_<CScriptPgpEngine>(m, "PgpEngine")
            .def(py::init<>())
            .def(py::init<const int>())
            .def(py::init<const PgpKeyAlgorithm>())
            .def("GetKeyAlgorithm", &CScriptPgpEngine::GetKeyAlgorithm)
            .def("GenerateKeyPair", static_cast<void (CScriptPgpEngine::*)(const std::string&, const std::string&)>(&CScriptPgpEngine::GenerateKeyPair))
            .def("GenerateKeyPair", static_cast<void (CScriptPgpEngine::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngine::GenerateKeyPair))
            .def("GetKeyExpirationSeconds", &CScriptPgpEngine::GetKeyExpirationSeconds)
            .def("ExportPublicKeyArmored", &CScriptPgpEngine::ExportPublicKeyArmored)
            .def("ExportSecretKeyArmored", &CScriptPgpEngine::ExportSecretKeyArmored)
            .def("GetKeyId", &CScriptPgpEngine::GetKeyId)
            .def("RevokeKeyArmored", &CScriptPgpEngine::RevokeKeyArmored)
            .def("ImportPeerPublicKey", static_cast<void (CScriptPgpEngine::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngine::ImportPeerPublicKey))
            .def("ImportPeerPublicKey", static_cast<void (CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportPeerPublicKey))
            .def("GetPeerKeyId", &CScriptPgpEngine::GetPeerKeyId)
            .def("ImportAdditionalRecipientPublicKey", static_cast<void (CScriptPgpEngine::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngine::ImportAdditionalRecipientPublicKey))
            .def("ImportAdditionalRecipientPublicKey", static_cast<void (CScriptPgpEngine::*)(const std::string&)>(&CScriptPgpEngine::ImportAdditionalRecipientPublicKey))
            .def("EncryptBuffer", &CScriptPgpEngine::EncryptBuffer)
            .def("EncryptStringArmored", &CScriptPgpEngine::EncryptStringArmored)
            .def("DecryptBuffer", &CScriptPgpEngine::DecryptBuffer)
            .def("DecryptStringArmored", &CScriptPgpEngine::DecryptStringArmored)
            .def("SignBuffer", &CScriptPgpEngine::SignBuffer)
            .def("VerifyBuffer", &CScriptPgpEngine::VerifyBuffer)
            .def("ClearSignString", &CScriptPgpEngine::ClearSignString)
            .def("VerifyClearSignedString", &CScriptPgpEngine::VerifyClearSignedString)
            .def("EncryptFile", &CScriptPgpEngine::EncryptFile)
            .def("EncryptFileCompressed", &CScriptPgpEngine::EncryptFileCompressed)
            .def("DecryptFile", &CScriptPgpEngine::DecryptFile)
            .def("SignFile", &CScriptPgpEngine::SignFile)
            .def("VerifyFile", &CScriptPgpEngine::VerifyFile)
            .def("IsPublicKeyEncrypted", &CScriptPgpEngine::IsPublicKeyEncrypted)
            .def("IsPasswordEncrypted", &CScriptPgpEngine::IsPasswordEncrypted)
            .def("IsIntegrityProtected", &CScriptPgpEngine::IsIntegrityProtected)
            .def("GetCompression", &CScriptPgpEngine::GetCompression)
            .def("ListEncryptionKeyIds", &CScriptPgpEngine::ListEncryptionKeyIds)
            .def("ListSigningKeyIds", &CScriptPgpEngine::ListSigningKeyIds)
            .def("ListSignatures", &CScriptPgpEngine::ListSignatures)
            ;

        py::class_<CScriptPgpEngineWrapper>(m, "PgpEngineWrapper")
            .def(py::init<>())
            .def(py::init<const int>())
            .def("IsGnuPgAvailable", &CScriptPgpEngineWrapper::IsGnuPgAvailable)
            .def("GenerateKeyPair", static_cast<void (CScriptPgpEngineWrapper::*)(const std::string&, const std::string&)>(&CScriptPgpEngineWrapper::GenerateKeyPair))
            .def("GenerateKeyPair", static_cast<void (CScriptPgpEngineWrapper::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngineWrapper::GenerateKeyPair))
            .def("GenerateKeyPairEcc", static_cast<void (CScriptPgpEngineWrapper::*)(const std::string&, const std::string&)>(&CScriptPgpEngineWrapper::GenerateKeyPairEcc))
            .def("GenerateKeyPairEcc", static_cast<void (CScriptPgpEngineWrapper::*)(const std::string&, const std::string&, const unsigned int)>(&CScriptPgpEngineWrapper::GenerateKeyPairEcc))
            .def("GetKeyExpirationSeconds", &CScriptPgpEngineWrapper::GetKeyExpirationSeconds)
            .def("ExportPublicKeyArmored", &CScriptPgpEngineWrapper::ExportPublicKeyArmored)
            .def("ExportSecretKeyArmored", &CScriptPgpEngineWrapper::ExportSecretKeyArmored)
            .def("GetKeyId", &CScriptPgpEngineWrapper::GetKeyId)
            .def("RevokeKeyArmored", &CScriptPgpEngineWrapper::RevokeKeyArmored)
            .def("ImportPeerPublicKey", static_cast<void (CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngineWrapper::ImportPeerPublicKey))
            .def("ImportPeerPublicKey", static_cast<void (CScriptPgpEngineWrapper::*)(const std::string&)>(&CScriptPgpEngineWrapper::ImportPeerPublicKey))
            .def("GetPeerKeyId", &CScriptPgpEngineWrapper::GetPeerKeyId)
            .def("GetImportedPeerKeyCount", &CScriptPgpEngineWrapper::GetImportedPeerKeyCount)
            .def("GetImportedPeerKeyId", &CScriptPgpEngineWrapper::GetImportedPeerKeyId)
            .def("GetKeyringListing", &CScriptPgpEngineWrapper::GetKeyringListing)
            .def("GetKeyringKeyCount", &CScriptPgpEngineWrapper::GetKeyringKeyCount)
            .def("GetKeyringKeyId", &CScriptPgpEngineWrapper::GetKeyringKeyId)
            .def("DeletePeerPublicKey", &CScriptPgpEngineWrapper::DeletePeerPublicKey)
            .def("DeleteOwnIdentity", &CScriptPgpEngineWrapper::DeleteOwnIdentity)
            .def("EncryptBuffer", static_cast<std::vector<unsigned char> (CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&)>(&CScriptPgpEngineWrapper::EncryptBuffer))
            .def("EncryptBuffer", static_cast<std::vector<unsigned char> (CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptBuffer))
            .def("EncryptStringArmored", static_cast<std::string (CScriptPgpEngineWrapper::*)(const std::string&)>(&CScriptPgpEngineWrapper::EncryptStringArmored))
            .def("EncryptStringArmored", static_cast<std::string (CScriptPgpEngineWrapper::*)(const std::string&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptStringArmored))
            .def("EncryptBufferSymmetric", &CScriptPgpEngineWrapper::EncryptBufferSymmetric)
            .def("EncryptStringArmoredSymmetric", &CScriptPgpEngineWrapper::EncryptStringArmoredSymmetric)
            .def("EncryptBufferMultiRecipient", static_cast<std::vector<unsigned char> (CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const std::vector<std::string>&)>(&CScriptPgpEngineWrapper::EncryptBufferMultiRecipient))
            .def("EncryptBufferMultiRecipient", static_cast<std::vector<unsigned char> (CScriptPgpEngineWrapper::*)(const std::vector<unsigned char>&, const std::vector<std::string>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptBufferMultiRecipient))
            .def("EncryptStringArmoredMultiRecipient", static_cast<std::string (CScriptPgpEngineWrapper::*)(const std::string&, const std::vector<std::string>&)>(&CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient))
            .def("EncryptStringArmoredMultiRecipient", static_cast<std::string (CScriptPgpEngineWrapper::*)(const std::string&, const std::vector<std::string>&, const PgpCompressionAlgorithm)>(&CScriptPgpEngineWrapper::EncryptStringArmoredMultiRecipient))
            .def("DecryptBuffer", &CScriptPgpEngineWrapper::DecryptBuffer)
            .def("DecryptStringArmored", &CScriptPgpEngineWrapper::DecryptStringArmored)
            .def("SignBuffer", &CScriptPgpEngineWrapper::SignBuffer)
            .def("VerifyBuffer", &CScriptPgpEngineWrapper::VerifyBuffer)
            .def("ClearSignString", &CScriptPgpEngineWrapper::ClearSignString)
            .def("VerifyClearSignedString", &CScriptPgpEngineWrapper::VerifyClearSignedString)
            .def("EncryptFile", &CScriptPgpEngineWrapper::EncryptFile)
            .def("DecryptFile", &CScriptPgpEngineWrapper::DecryptFile)
            .def("SignFile", &CScriptPgpEngineWrapper::SignFile)
            .def("VerifyFile", &CScriptPgpEngineWrapper::VerifyFile)
            .def("IsPublicKeyEncrypted", &CScriptPgpEngineWrapper::IsPublicKeyEncrypted)
            .def("IsPasswordEncrypted", &CScriptPgpEngineWrapper::IsPasswordEncrypted)
            .def("IsIntegrityProtected", &CScriptPgpEngineWrapper::IsIntegrityProtected)
            .def("GetCompression", &CScriptPgpEngineWrapper::GetCompression)
            .def("ListEncryptionKeyIds", &CScriptPgpEngineWrapper::ListEncryptionKeyIds)
            .def("ListSigningKeyIds", &CScriptPgpEngineWrapper::ListSigningKeyIds)
            .def("ListSignatures", &CScriptPgpEngineWrapper::ListSignatures)
            ;

        // CertificateKeyAlgorithm/CertificateDigestAlgorithm/RevocationMode/RevocationNetworkMode/
        // CertificateTrustResult/RevocationStatus/CmsVerificationResult/TimestampVerificationResult
        // are passed/returned as plain ints here (see CScriptCertificateManager.h's own header
        // comment) rather than getting their own py::enum_ -- a deliberate, documented departure
        // from this file's own usual "every enum gets py::enum_+export_values()" convention, made
        // for the same disproportionate-registration-cost reasoning as every other engine's
        // binding for these three classes.
        py::class_<CScriptCertificateManager>(m, "CertificateManager")
            .def(py::init<>())
            .def("GetCertificateInfoText", &CScriptCertificateManager::GetCertificateInfoText)
            .def("ConvertCertificateDerToPem", &CScriptCertificateManager::ConvertCertificateDerToPem)
            .def("ConvertCertificatePemToDer", &CScriptCertificateManager::ConvertCertificatePemToDer)
            .def("CreateSelfSignedCertificate", &CScriptCertificateManager::CreateSelfSignedCertificate)
            .def("CreateCertificateRequest", &CScriptCertificateManager::CreateCertificateRequest)
            .def("GetLastPrivateKeyPem", &CScriptCertificateManager::GetLastPrivateKeyPem)
            .def("IssueCertificateFromRequest", &CScriptCertificateManager::IssueCertificateFromRequest)
            .def("AddIntermediateCertificateForChainValidation", &CScriptCertificateManager::AddIntermediateCertificateForChainValidation)
            .def("ClearIntermediateCertificatesForChainValidation", &CScriptCertificateManager::ClearIntermediateCertificatesForChainValidation)
            .def("ValidateChain", &CScriptCertificateManager::ValidateChain)
            .def("GetLastRevocationStatus", &CScriptCertificateManager::GetLastRevocationStatus)
            ;

        py::class_<CScriptCmsService>(m, "CmsService")
            .def(py::init<>())
            .def("SignDetached", &CScriptCmsService::SignDetached)
            .def("VerifyDetached", &CScriptCmsService::VerifyDetached)
            .def("ExtractSignerCertificate", &CScriptCmsService::ExtractSignerCertificate)
            ;

        py::class_<CScriptTimestampService>(m, "TimestampService")
            .def(py::init<>())
            .def("CreateTimestampRequest", &CScriptTimestampService::CreateTimestampRequest)
            .def("RequestTimestampFromTsa", &CScriptTimestampService::RequestTimestampFromTsa)
            .def("VerifyTimestampResponse", &CScriptTimestampService::VerifyTimestampResponse)
            .def("GetTimestampInfoText", &CScriptTimestampService::GetTimestampInfoText)
            ;
#endif // !DLL_RUNNER

    // DLL-hosted facades (CScriptCryptoApiDll/CScriptPgpEngineDll/CScriptPgpEngineWrapperDll) --
    // lightweight, no CCryptoApi/CPgpEngine/CPgpEngineWrapper dependency, so registered
    // unconditionally (harmless for AppBuilder, required for DllRunner). No py::init<...>() is
    // added -- pybind11 classes are simply not Python-constructible without one, so these are
    // only ever pushed as an already-constructed instance via SetDllCryptoApi/SetDllPgpEngine/
    // SetDllPgpEngineWrapper below, never a script's own constructor call.
    py::class_<CScriptCryptoApiDll>(m, "CryptoApiDll")
        .def("GetVersion", &CScriptCryptoApiDll::GetVersion)
        .def("GetHashSize", &CScriptCryptoApiDll::GetHashSize)
        .def("ComputeHashString", &CScriptCryptoApiDll::ComputeHashString)
        .def("EncryptFileWithProgress", &CScriptCryptoApiDll::EncryptFile)
        .def("DecryptFileWithProgress", &CScriptCryptoApiDll::DecryptFile)
        ;

    py::class_<CScriptPgpEngineDll>(m, "PgpEngineDll")
        .def("GenerateKeyPair", &CScriptPgpEngineDll::GenerateKeyPair)
        .def("ExportPublicKeyArmored", &CScriptPgpEngineDll::ExportPublicKeyArmored)
        .def("ImportPeerPublicKey", &CScriptPgpEngineDll::ImportPeerPublicKey)
        .def("EncryptStringArmored", &CScriptPgpEngineDll::EncryptStringArmored)
        .def("DecryptStringArmored", &CScriptPgpEngineDll::DecryptStringArmored)
        ;

    py::class_<CScriptPgpEngineWrapperDll>(m, "PgpEngineWrapperDll")
        .def("IsGnuPgAvailable", &CScriptPgpEngineWrapperDll::IsGnuPgAvailable)
        .def("GenerateKeyPair", &CScriptPgpEngineWrapperDll::GenerateKeyPair)
        .def("ExportPublicKeyArmored", &CScriptPgpEngineWrapperDll::ExportPublicKeyArmored)
        .def("ImportPeerPublicKey", &CScriptPgpEngineWrapperDll::ImportPeerPublicKey)
        .def("EncryptStringArmored", &CScriptPgpEngineWrapperDll::EncryptStringArmored)
        .def("DecryptStringArmored", &CScriptPgpEngineWrapperDll::DecryptStringArmored)
        ;

    py::class_<CScriptCertificateManagerDll>(m, "CertificateManagerDll")
        .def("CreateSelfSignedCertificate", &CScriptCertificateManagerDll::CreateSelfSignedCertificate)
        .def("GetLastPrivateKeyPem", &CScriptCertificateManagerDll::GetLastPrivateKeyPem)
        .def("GetCertificateInfoText", &CScriptCertificateManagerDll::GetCertificateInfoText)
        ;

    py::class_<CScriptCmsServiceDll>(m, "CmsServiceDll")
        .def("SignDetached", &CScriptCmsServiceDll::SignDetached)
        .def("VerifyDetached", &CScriptCmsServiceDll::VerifyDetached)
        ;

    py::class_<CScriptTimestampServiceDll>(m, "TimestampServiceDll")
        .def("CreateTimestampRequest", &CScriptTimestampServiceDll::CreateTimestampRequest)
        .def("RequestTimestampFromTsa", &CScriptTimestampServiceDll::RequestTimestampFromTsa)
        .def("GetTimestampInfoText", &CScriptTimestampServiceDll::GetTimestampInfoText)
        ;
} // this closes the PYBIND11_EMBEDDED_MODULE function body opened at "PYBIND11_EMBEDDED_MODULE(
  // cryptoapi_native, m)\n{" above -- namespace CryptoApiNS itself, opened at the top of this
  // file, is still open here and remains open for everything below.
// -----------------------------------------------------------------------------

CPythonScriptEngine::~CPythonScriptEngine()
{
    if (--g_pythonInterpreterRefCount == 0)
    {
        py::finalize_interpreter();
    }
}
// -----------------------------------------------------------------------------

CPythonScriptEngine::CPythonScriptEngine()
{
    if (++g_pythonInterpreterRefCount == 1)
    {
        PyConfig config;
        PyConfig_InitPythonConfig(&config);
        config.parse_argv = 0;

        std::wstring exeDir = getExecutableDirectory();
        if (!exeDir.empty())
        {
            // Explicit module search path: bypasses CPython's usual registry/landmark-file path
            // discovery (which assumes either a full install or python.exe's own ._pth-based
            // isolated mode) entirely -- AppBuilder.exe is neither, so this is the documented way to
            // point an embedded interpreter straight at the exact files the PostBuildEvent step
            // (AppBuilder.vcxproj's Python x64-only ItemDefinitionGroup) copies next to it:
            // python312.zip for the stdlib, and the executable's own directory for any loose *.pyd
            // extension modules (_socket, _ssl, etc.) alongside their supporting DLLs.
            config.module_search_paths_set = 1;
            std::wstring stdlibZip = exeDir + L"\\python312.zip";
            PyWideStringList_Append(&config.module_search_paths, stdlibZip.c_str());
            PyWideStringList_Append(&config.module_search_paths, exeDir.c_str());
            PyConfig_SetString(&config, &config.home, exeDir.c_str());
        }

        py::initialize_interpreter(&config);
    }

    registerBindings();
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::RunFile(const std::string& filePath)
{
    try
    {
        py::object globals = py::globals();
        py::eval_file(filePath, globals, globals);
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("RunFile: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::RunString(const std::string& code)
{
    try
    {
        py::object globals = py::globals();
        py::exec(code, globals, globals);
    }
    catch (const std::exception& ex)
    {
        throw CScriptException(UNEXPECTED_ERROR, std::string("RunString: ") + ex.what());
    }
}
// -----------------------------------------------------------------------------

bool CPythonScriptEngine::GetGlobalBool(const std::string& name)
{
    try
    {
        py::dict globals = py::globals();
        if (!globals.contains(name))
        {
            return false;
        }

        return globals[name.c_str()].cast<bool>();
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

int CPythonScriptEngine::GetGlobalInt(const std::string& name)
{
    try
    {
        py::dict globals = py::globals();
        if (!globals.contains(name))
        {
            return 0;
        }

        return globals[name.c_str()].cast<int>();
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

std::string CPythonScriptEngine::GetGlobalString(const std::string& name)
{
    try
    {
        py::dict globals = py::globals();
        if (!globals.contains(name))
        {
            return std::string();
        }

        return globals[name.c_str()].cast<std::string>();
    }
    catch (...)
    {
        return std::string();
    }
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::registerBindings(void)
{
    py::object globals = py::globals();
    py::exec("from cryptoapi_native import *", globals, globals);
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllCryptoApi(CScriptCryptoApiDll* api)
{
    try
    {
        py::globals()["cryptoApi"] = py::cast(api, py::return_value_policy::reference);
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllPgpEngine(CScriptPgpEngineDll* engine)
{
    try
    {
        py::globals()["pgpEngine"] = py::cast(engine, py::return_value_policy::reference);
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllPgpEngineWrapper(CScriptPgpEngineWrapperDll* wrapper)
{
    try
    {
        py::globals()["pgpEngineWrapper"] = py::cast(wrapper, py::return_value_policy::reference);
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllCertificateManager(CScriptCertificateManagerDll* manager)
{
    try
    {
        py::globals()["certificateManager"] = py::cast(manager, py::return_value_policy::reference);
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllCmsService(CScriptCmsServiceDll* service)
{
    try
    {
        py::globals()["cmsService"] = py::cast(service, py::return_value_policy::reference);
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllTimestampService(CScriptTimestampServiceDll* service)
{
    try
    {
        py::globals()["timestampService"] = py::cast(service, py::return_value_policy::reference);
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#else // !CRYPTOAPI_PYTHON_AVAILABLE

#include "../ScriptException.h"
#include "../ScriptCryptoApiDll.h"
#include "../ScriptPgpEngineDll.h"
#include "../ScriptPgpEngineWrapperDll.h"
#include "../ScriptCertificateManagerDll.h"
#include "../ScriptCmsServiceDll.h"
#include "../ScriptTimestampServiceDll.h"

namespace CryptoApiNS
{

CPythonScriptEngine::~CPythonScriptEngine()
{
}
// -----------------------------------------------------------------------------

CPythonScriptEngine::CPythonScriptEngine()
{
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::RunFile(const std::string& filePath)
{
    (void)filePath;
    throw CScriptException(NOT_IMPLEMENTED, "RunFile: Python scripting requires an x64 build (no Win32 CPython binary is vendored)");
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::RunString(const std::string& code)
{
    (void)code;
    throw CScriptException(NOT_IMPLEMENTED, "RunString: Python scripting requires an x64 build (no Win32 CPython binary is vendored)");
}
// -----------------------------------------------------------------------------

bool CPythonScriptEngine::GetGlobalBool(const std::string& name)
{
    (void)name;
    return false;
}
// -----------------------------------------------------------------------------

int CPythonScriptEngine::GetGlobalInt(const std::string& name)
{
    (void)name;
    return 0;
}
// -----------------------------------------------------------------------------

std::string CPythonScriptEngine::GetGlobalString(const std::string& name)
{
    (void)name;
    return std::string();
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::registerBindings(void)
{
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllCryptoApi(CScriptCryptoApiDll* api)
{
    (void)api;
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllPgpEngine(CScriptPgpEngineDll* engine)
{
    (void)engine;
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllPgpEngineWrapper(CScriptPgpEngineWrapperDll* wrapper)
{
    (void)wrapper;
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllCertificateManager(CScriptCertificateManagerDll* manager)
{
    (void)manager;
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllCmsService(CScriptCmsServiceDll* service)
{
    (void)service;
}
// -----------------------------------------------------------------------------

void CPythonScriptEngine::SetDllTimestampService(CScriptTimestampServiceDll* service)
{
    (void)service;
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

#endif // CRYPTOAPI_PYTHON_AVAILABLE

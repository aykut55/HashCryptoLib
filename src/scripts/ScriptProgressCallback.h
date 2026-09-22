#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_PROGRESS_CALLBACK_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_PROGRESS_CALLBACK_H

#include <functional>

namespace CryptoApiNS
{

// C++-calls-INTO-script direction: a script passes one of these (a native script function; every
// binding library converts it to this signature automatically when it sees a bound C++ parameter
// of this exact type) to a EncryptFileWithProgress/DecryptFileWithProgress-style method, and the
// underlying engine's own chunked file loop calls it once per chunk via the raw C-ABI
// ProgressCallback (Definitions.h) -- see each facade's own scriptProgressTrampoline for the
// bridge between the two. Same (currentByte, totalByte, percentage) -> bool "continue?" contract
// ProgressCallback itself documents; returning false aborts the operation with
// OPERATION_CANCELLED at the next chunk boundary, exactly as it would for a native C++ caller.
//
// Lives in its own tiny header (rather than inline in ScriptCryptoApi.h, where it originated)
// specifically so CScriptCryptoApiDll (ScriptCryptoApiDll.h) can use the exact same type without
// pulling in CryptoApi.h's own heavy CCryptoApi/provider-stack dependency -- see
// ScriptCryptoApiDll.h's own header comment for why that dependency must never leak into a
// DLL-only host (DllRunner).
using ScriptProgressCallback = std::function<bool(unsigned long long, unsigned long long, double)>;

} // namespace CryptoApiNS

#endif

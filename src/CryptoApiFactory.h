#ifndef CRYPTOAPI_CRYPTO_API_FACTORY_H
#define CRYPTOAPI_CRYPTO_API_FACTORY_H

#include "CryptoApi.h"
#include "CryptoApiTester.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"

// extern "C" DLL entry points resolved by CCryptoApiDllLoader via GetProcAddress (see
// DllLoader/CryptoApiDllLoader.h) -- not part of the CryptoApiNS namespace since C linkage cannot
// be namespaced. Construction/destruction of the concrete CCryptoApi/CCryptoApiTester always
// happens inside the DLL that defines these; a caller that only dynamically loaded that DLL
// interacts with the returned object exclusively through ICryptoApi/ICryptoApiTester (virtual
// dispatch), never through the concrete classes themselves.
extern "C" CRYPTOAPI_API CryptoApiNS::ICryptoApi* CreateCryptoApi(void);
extern "C" CRYPTOAPI_API void					  DestroyCryptoApi(CryptoApiNS::ICryptoApi* pCryptoApi);

extern "C" CRYPTOAPI_API CryptoApiNS::ICryptoApiTester* CreateCryptoApiTester(void);
extern "C" CRYPTOAPI_API void						  DestroyCryptoApiTester(CryptoApiNS::ICryptoApiTester* pCryptoApiTester);

// Same reasoning as CreateCryptoApi/DestroyCryptoApi above, for CPgpEngine/IPgpEngine. Always
// default-constructs (new CryptoApiNS::CPgpEngine()) -- CPgpEngine's other two constructors
// (rsaKeyBits/keyAlgorithm) are unreachable through this DLL boundary, the same limitation
// CreateCryptoApi() already has for CCryptoApi's own many constructor overloads (see that
// function's .cpp comment).
extern "C" CRYPTOAPI_API CryptoApiNS::IPgpEngine* CreatePgpEngine(void);
extern "C" CRYPTOAPI_API void					  DestroyPgpEngine(CryptoApiNS::IPgpEngine* pPgpEngine);

// Same reasoning, for CPgpEngineWrapper/IPgpEngineWrapper. Always default-constructs; the
// rsaKeyBits constructor is unreachable through this DLL boundary for the same reason.
extern "C" CRYPTOAPI_API CryptoApiNS::IPgpEngineWrapper* CreatePgpEngineWrapper(void);
extern "C" CRYPTOAPI_API void						  DestroyPgpEngineWrapper(CryptoApiNS::IPgpEngineWrapper* pPgpEngineWrapper);

#endif

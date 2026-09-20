// This header is intentionally inert: CCryptoApi is exported directly via CRYPTOAPI_API in
// ..\..\..\src\CryptoApi.h (DllBuilder.vcxproj defines CRYPTOAPI_DLL_EXPORTS), so there is nothing
// left for this file to declare. The original Visual Studio wizard scaffolding is kept below,
// commented out, as a placeholder in case a DLL-only helper (version query, capability probe, etc.
// that isn't part of CCryptoApi itself) is ever needed here.

// #define DLLBUILDER_API __declspec(dllexport)
// #define DLLBUILDER_API __declspec(dllimport)

/*
#ifdef DLLBUILDER_EXPORTS
#define DLLBUILDER_API __declspec(dllexport)
#else
#define DLLBUILDER_API __declspec(dllimport)
#endif

// This class is exported from the dll
class DLLBUILDER_API CDllBuilder {
public:
	CDllBuilder(void);
	// TODO: add your methods here.
};

extern DLLBUILDER_API int nDllBuilder;

DLLBUILDER_API int fnDllBuilder(void);
*/

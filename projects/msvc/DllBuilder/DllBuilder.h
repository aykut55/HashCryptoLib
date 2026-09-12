// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the DLLBUILDER_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// DLLBUILDER_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
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

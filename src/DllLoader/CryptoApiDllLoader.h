#pragma once
//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// windows.h #defines LoadLibrary to LoadLibraryA/LoadLibraryW depending on UNICODE (our MSVC
// projects build with CharacterSet=Unicode, so it would silently become LoadLibraryW otherwise);
// undefining it lets CCryptoApiDllLoader::LoadLibrary keep that exact compiled name instead of
// being rewritten to LoadLibraryW. GetProcAddress has no such macro (it is always the single
// narrow-char entry point), so no equivalent #undef is needed for it.
#undef LoadLibrary
// windows.h (via WinError.h) also #defines NO_ERROR to 0L, which collides with CryptoApiNS's own
// ErrorCode::NO_ERROR enumerator (see Definitions.h) once ICryptoApi.h is included below; same
// guarded #undef pattern CryptoApi.cpp itself uses for EncryptFile/DecryptFile.
#ifdef NO_ERROR
#undef NO_ERROR
#endif
//---------------------------------------------------------------------------
#include <iostream>
#include <string>
#include "Interfaces/ICryptoApi.h"
#include "Interfaces/ICryptoApiTester.h"
#include "Interfaces/IPgpEngine.h"
#include "Interfaces/IPgpEngineWrapper.h"
//---------------------------------------------------------------------------

namespace CryptoApiNS
{

class CCryptoApiDllLoader
{
    typedef ICryptoApi*        (*CreateCryptoApiFunc)();
    typedef void                (*DestroyCryptoApiFunc)(ICryptoApi*);
    typedef ICryptoApiTester*  (*CreateCryptoApiTesterFunc)();
    typedef void                (*DestroyCryptoApiTesterFunc)(ICryptoApiTester*);
    typedef IPgpEngine*         (*CreatePgpEngineFunc)();
    typedef void                (*DestroyPgpEngineFunc)(IPgpEngine*);
    typedef IPgpEngineWrapper*  (*CreatePgpEngineWrapperFunc)();
    typedef void                (*DestroyPgpEngineWrapperFunc)(IPgpEngineWrapper*);

public:
    virtual ~CCryptoApiDllLoader();
             CCryptoApiDllLoader();

    void              SetFileName(std::string dllFileName);
    std::string       GetFileName(void);
    bool              LoadLibrary(void);
    bool              UnloadLibrary(void);
    bool              IsLoaded(void);
    bool              IsUnloaded(void);

    ICryptoApi*       GetCryptoApiObject();                                                 // Instance
    void              DestroyCryptoApiObject(ICryptoApi* pCryptoApi);                       // Destroys an instance returned by GetCryptoApiObject() above -- callers must use
                                                                                            // this instead of delete, since the instance was allocated inside the DLL.
    ICryptoApiTester* GetCryptoApiTesterObject();                                           // Instance
    void              DestroyCryptoApiTesterObject(ICryptoApiTester* pCryptoApiTester);     // Same reasoning as DestroyCryptoApiObject above.

    IPgpEngine*        GetPgpEngineObject();                                                 // Instance
    void               DestroyPgpEngineObject(IPgpEngine* pPgpEngine);                       // Same reasoning as DestroyCryptoApiObject above.
    IPgpEngineWrapper* GetPgpEngineWrapperObject();                                          // Instance
    void               DestroyPgpEngineWrapperObject(IPgpEngineWrapper* pPgpEngineWrapper);  // Same reasoning as DestroyCryptoApiObject above.

    void*             GetProcAddress(const char* functionName);                             // Resolves functionName's address in the DLL loaded by LoadLibrary() above; returns nullptr if
                                                                                            // LoadLibrary() has not succeeded yet, or the DLL has no export by that exact name.
protected:

private:
    std::string DllFileName;
    HINSTANCE hDll;
    CreateCryptoApiFunc CreateCryptoApi;
    DestroyCryptoApiFunc DestroyCryptoApi;
    CreateCryptoApiTesterFunc CreateCryptoApiTester;
    DestroyCryptoApiTesterFunc DestroyCryptoApiTester;
    CreatePgpEngineFunc CreatePgpEngine;
    DestroyPgpEngineFunc DestroyPgpEngine;
    CreatePgpEngineWrapperFunc CreatePgpEngineWrapper;
    DestroyPgpEngineWrapperFunc DestroyPgpEngineWrapper;
    bool isLoaded;
    bool isUnloaded;
};

} // namespace CryptoApiNS
//---------------------------------------------------------------------------

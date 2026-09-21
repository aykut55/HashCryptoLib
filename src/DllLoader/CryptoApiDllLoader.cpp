#pragma once
//---------------------------------------------------------------------------

#include "CryptoApiDllLoader.h"
//---------------------------------------------------------------------------

namespace CryptoApiNS
{

CCryptoApiDllLoader::~CCryptoApiDllLoader()
{
    try
    {
        //std::cout << "CCryptoApiDllLoader: Destructor Called" << std::endl;
        int result = FreeLibrary(hDll);
    }
    catch (...)
    {

    }
}
//---------------------------------------------------------------------------

CCryptoApiDllLoader::CCryptoApiDllLoader()
{
    try
    {
        //std::cout << "CCryptoApiDllLoader: Constructor Called" << std::endl;

        isLoaded = false;
        isUnloaded = false;
    }
    catch (...)
    {

    }
}
//---------------------------------------------------------------------------

void CCryptoApiDllLoader::SetFileName(std::string dllFileName)
{
    DllFileName = dllFileName;
}
//---------------------------------------------------------------------------

std::string CCryptoApiDllLoader::GetFileName(void)
{
    return DllFileName;
}
//---------------------------------------------------------------------------

bool CCryptoApiDllLoader::LoadLibrary(void)
{
    try
    {
        isLoaded = true;

        //std::cout << "CCryptoApiDllLoader: LoadLibrary Called" << std::endl;

        std::string dllFileName = GetFileName();

        hDll = LoadLibraryA(dllFileName.c_str());
        if (!hDll)
        {
            isLoaded = false;

            std::cerr << "DLL yüklenemedi! Hata kodu: " << GetLastError() << std::endl;
            return isLoaded;
        }

        // DLL'den fonksiyon adreslerini al
        CreateCryptoApi = (CreateCryptoApiFunc)::GetProcAddress(hDll, "CreateCryptoApi");
        if (!CreateCryptoApi)
        {
            isLoaded = false;

            std::cerr << "GetProcAddress başarısız! Hata kodu: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return isLoaded;
        }

        DestroyCryptoApi = (DestroyCryptoApiFunc)::GetProcAddress(hDll, "DestroyCryptoApi");
        if (!DestroyCryptoApi)
        {
            isLoaded = false;

            std::cerr << "GetProcAddress başarısız! Hata kodu: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return isLoaded;
        }

        CreateCryptoApiTester = (CreateCryptoApiTesterFunc)::GetProcAddress(hDll, "CreateCryptoApiTester");
        if (!CreateCryptoApiTester)
        {
            isLoaded = false;

            std::cerr << "GetProcAddress başarısız! Hata kodu: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return isLoaded;
        }

        DestroyCryptoApiTester = (DestroyCryptoApiTesterFunc)::GetProcAddress(hDll, "DestroyCryptoApiTester");
        if (!DestroyCryptoApiTester)
        {
            isLoaded = false;

            std::cerr << "GetProcAddress başarısız! Hata kodu: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return isLoaded;
        }

        CreatePgpEngine = (CreatePgpEngineFunc)::GetProcAddress(hDll, "CreatePgpEngine");
        if (!CreatePgpEngine)
        {
            isLoaded = false;

            std::cerr << "GetProcAddress başarısız! Hata kodu: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return isLoaded;
        }

        DestroyPgpEngine = (DestroyPgpEngineFunc)::GetProcAddress(hDll, "DestroyPgpEngine");
        if (!DestroyPgpEngine)
        {
            isLoaded = false;

            std::cerr << "GetProcAddress başarısız! Hata kodu: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return isLoaded;
        }

        CreatePgpEngineWrapper = (CreatePgpEngineWrapperFunc)::GetProcAddress(hDll, "CreatePgpEngineWrapper");
        if (!CreatePgpEngineWrapper)
        {
            isLoaded = false;

            std::cerr << "GetProcAddress başarısız! Hata kodu: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return isLoaded;
        }

        DestroyPgpEngineWrapper = (DestroyPgpEngineWrapperFunc)::GetProcAddress(hDll, "DestroyPgpEngineWrapper");
        if (!DestroyPgpEngineWrapper)
        {
            isLoaded = false;

            std::cerr << "GetProcAddress başarısız! Hata kodu: " << GetLastError() << std::endl;
            FreeLibrary(hDll);
            return isLoaded;
        }
    }
    catch (...)
    {

    }

    return isLoaded;
}
//---------------------------------------------------------------------------

bool CCryptoApiDllLoader::UnloadLibrary(void)
{
    try
    {
        isUnloaded = false;

        int result = FreeLibrary(hDll);
        if (result != 0)
            isUnloaded = true;
    }
    catch (...)
    {

    }

    return isUnloaded;
}
//---------------------------------------------------------------------------

bool CCryptoApiDllLoader::IsLoaded(void)
{
    return isLoaded;
}
//---------------------------------------------------------------------------

bool CCryptoApiDllLoader::IsUnloaded(void)
{
    return isUnloaded;
}
//---------------------------------------------------------------------------

ICryptoApi* CCryptoApiDllLoader::GetCryptoApiObject()
{
    ICryptoApi* pCryptoApi = 0;

    try
    {
        pCryptoApi = CreateCryptoApi();
    }
    catch (...)
    {

    }

    return pCryptoApi;
}
//---------------------------------------------------------------------------

void CCryptoApiDllLoader::DestroyCryptoApiObject(ICryptoApi* pCryptoApi)
{
    try
    {
        DestroyCryptoApi(pCryptoApi);
        pCryptoApi = 0;
    }
    catch (...)
    {

    }
}
//---------------------------------------------------------------------------

ICryptoApiTester* CCryptoApiDllLoader::GetCryptoApiTesterObject()
{
    ICryptoApiTester* pCryptoApiTester = 0;

    try
    {
        pCryptoApiTester = CreateCryptoApiTester();
    }
    catch (...)
    {

    }

    return pCryptoApiTester;
}
//---------------------------------------------------------------------------

void CCryptoApiDllLoader::DestroyCryptoApiTesterObject(ICryptoApiTester* pCryptoApiTester)
{
    try
    {
        DestroyCryptoApiTester(pCryptoApiTester);
        pCryptoApiTester = 0;
    }
    catch (...)
    {

    }
}
//---------------------------------------------------------------------------

IPgpEngine* CCryptoApiDllLoader::GetPgpEngineObject()
{
    IPgpEngine* pPgpEngine = 0;

    try
    {
        pPgpEngine = CreatePgpEngine();
    }
    catch (...)
    {

    }

    return pPgpEngine;
}
//---------------------------------------------------------------------------

void CCryptoApiDllLoader::DestroyPgpEngineObject(IPgpEngine* pPgpEngine)
{
    try
    {
        DestroyPgpEngine(pPgpEngine);
        pPgpEngine = 0;
    }
    catch (...)
    {

    }
}
//---------------------------------------------------------------------------

IPgpEngineWrapper* CCryptoApiDllLoader::GetPgpEngineWrapperObject()
{
    IPgpEngineWrapper* pPgpEngineWrapper = 0;

    try
    {
        pPgpEngineWrapper = CreatePgpEngineWrapper();
    }
    catch (...)
    {

    }

    return pPgpEngineWrapper;
}
//---------------------------------------------------------------------------

void CCryptoApiDllLoader::DestroyPgpEngineWrapperObject(IPgpEngineWrapper* pPgpEngineWrapper)
{
    try
    {
        DestroyPgpEngineWrapper(pPgpEngineWrapper);
        pPgpEngineWrapper = 0;
    }
    catch (...)
    {

    }
}
//---------------------------------------------------------------------------

void* CCryptoApiDllLoader::GetProcAddress(const char* functionName)
{
    try
    {
        if (!hDll)
        {
            return nullptr;
        }

        return reinterpret_cast<void*>(::GetProcAddress(hDll, functionName));
    }
    catch (...)
    {
        return nullptr;
    }
}
//---------------------------------------------------------------------------

} // namespace CryptoApiNS
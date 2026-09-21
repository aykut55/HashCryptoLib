#include "CryptoApiFactory.h"

CryptoApiNS::ICryptoApi* CreateCryptoApi(void)
{
    try
    {
        return new CryptoApiNS::CCryptoApi();
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

void DestroyCryptoApi(CryptoApiNS::ICryptoApi* pCryptoApi)
{
    try
    {
        delete pCryptoApi;
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

CryptoApiNS::ICryptoApiTester* CreateCryptoApiTester(void)
{
    try
    {
        return new CryptoApiNS::CCryptoApiTester();
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

void DestroyCryptoApiTester(CryptoApiNS::ICryptoApiTester* pCryptoApiTester)
{
    try
    {
        delete pCryptoApiTester;
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

CryptoApiNS::IPgpEngine* CreatePgpEngine(void)
{
    try
    {
        return new CryptoApiNS::CPgpEngine();
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

void DestroyPgpEngine(CryptoApiNS::IPgpEngine* pPgpEngine)
{
    try
    {
        delete pPgpEngine;
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

CryptoApiNS::IPgpEngineWrapper* CreatePgpEngineWrapper(void)
{
    try
    {
        return new CryptoApiNS::CPgpEngineWrapper();
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

void DestroyPgpEngineWrapper(CryptoApiNS::IPgpEngineWrapper* pPgpEngineWrapper)
{
    try
    {
        delete pPgpEngineWrapper;
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

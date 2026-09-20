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

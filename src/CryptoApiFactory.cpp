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

CryptoApiNS::ICertificateManager* CreateCertificateManager(void)
{
    try
    {
        return new CryptoApiNS::CCertificateManager();
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

void DestroyCertificateManager(CryptoApiNS::ICertificateManager* pCertificateManager)
{
    try
    {
        delete pCertificateManager;
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

CryptoApiNS::ICmsService* CreateCmsService(void)
{
    try
    {
        return new CryptoApiNS::CCmsService();
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

void DestroyCmsService(CryptoApiNS::ICmsService* pCmsService)
{
    try
    {
        delete pCmsService;
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

CryptoApiNS::ITimestampService* CreateTimestampService(void)
{
    try
    {
        return new CryptoApiNS::CTimestampService();
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

void DestroyTimestampService(CryptoApiNS::ITimestampService* pTimestampService)
{
    try
    {
        delete pTimestampService;
    }
    catch (...)
    {

    }
}
// -----------------------------------------------------------------------------

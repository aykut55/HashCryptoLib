#include <iostream>

#include "DllLoader/CryptoApiDllLoader.h"

int main()
{
    std::string dllFileName = "CryptoApi.dll";

    CryptoApiNS::CCryptoApiDllLoader* pCryptoApiDllLoader = nullptr;

	CryptoApiNS::ICryptoApi* pCryptoApi = nullptr;

    try
    {
        std::cout << "Hello World!\n";
        std::cout << std::endl;

        pCryptoApiDllLoader = new CryptoApiNS::CCryptoApiDllLoader();

        if (pCryptoApiDllLoader)
        {
            pCryptoApiDllLoader->SetFileName(dllFileName);

            if (pCryptoApiDllLoader->LoadLibrary())
            {
                std::cout << "CryptoApi.dll loaded successfully." << std::endl;
            }
            else
            {
                std::cout << "Failed to load CryptoApi.dll." << std::endl;
            }

            if (pCryptoApiDllLoader->IsLoaded())
            {
                pCryptoApi = pCryptoApiDllLoader->GetCryptoApiObject();

                if (pCryptoApi)
                {
                    std::cout << std::endl;

                    std::cout << "CryptoAPI version: " << pCryptoApi->GetVersion() << std::endl;

                    std::cout << std::endl;

                    // testleri kostur..
                    CryptoApiNS::ICryptoApiTester* pCryptoApiTester = pCryptoApiDllLoader->GetCryptoApiTesterObject();

                    if (pCryptoApiTester)
                    {
                        pCryptoApiTester->RunEncryptDecryptFileTest();

                        pCryptoApiTester->RunEncryptDecryptStringTest();

                        pCryptoApiTester->RunEncryptDecryptBufferTest();

                        pCryptoApiTester->RunEncryptDecryptBytesTest();

                        pCryptoApiDllLoader->DestroyCryptoApiTesterObject(pCryptoApiTester);
                    }
                }

                pCryptoApiDllLoader->DestroyCryptoApiObject(pCryptoApi);
            }
        }

        delete pCryptoApiDllLoader;
    }
    catch (...)
    {

    }

    return 0;
}

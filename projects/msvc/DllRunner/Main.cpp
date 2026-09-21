#include <iostream>
#include <string>
#include <vector>
#include <cstring>

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

            if (pCryptoApiDllLoader->IsLoaded())
            {
                // IPgpEngine round trip through the DLL boundary: GenerateKeyPair, export this
                // instance's own public key, re-import it as its own "peer" (a self-contained
                // Alice-to-Alice round trip, same pattern CCryptoApiTester's own PGP tests use),
                // encrypt, decrypt, and compare -- proves the DLL's CreatePgpEngine()/IPgpEngine
                // virtual dispatch works end to end, not just that it links.
                CryptoApiNS::IPgpEngine* pPgpEngine = pCryptoApiDllLoader->GetPgpEngineObject();

                if (pPgpEngine)
                {
                    std::cout << std::endl;

                    const char* userId = "DllRunner Test <dllrunner@example.com>";
                    const char* password = "DllRunnerTestPassword123";
                    const char* plaintext = "Hello from DllRunner via IPgpEngine!";

                    int rc = pPgpEngine->GenerateKeyPair(userId, static_cast<int>(strlen(userId)),
                                                        password, static_cast<int>(strlen(password)));

                    if (rc == CryptoApiNS::NO_ERROR)
                    {
                        int pubKeySize = 0;
                        pPgpEngine->ExportPublicKeyArmored(0, nullptr, &pubKeySize);

                        std::vector<char> pubKeyBuffer(pubKeySize);
                        pPgpEngine->ExportPublicKeyArmored(pubKeySize, pubKeyBuffer.data(), &pubKeySize);

                        pPgpEngine->ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(pubKeyBuffer.data()), pubKeySize);

                        int cipherSize = 0;
                        pPgpEngine->EncryptStringArmored(plaintext, static_cast<int>(strlen(plaintext)), 0, nullptr, &cipherSize);

                        std::vector<char> cipherBuffer(cipherSize);
                        pPgpEngine->EncryptStringArmored(plaintext, static_cast<int>(strlen(plaintext)), cipherSize, cipherBuffer.data(), &cipherSize);

                        int plainSize = 0;
                        pPgpEngine->DecryptStringArmored(password, static_cast<int>(strlen(password)),
                                                        cipherBuffer.data(), cipherSize, 0, nullptr, &plainSize);

                        std::vector<unsigned char> plainBuffer(plainSize);
                        pPgpEngine->DecryptStringArmored(password, static_cast<int>(strlen(password)),
                                                        cipherBuffer.data(), cipherSize, plainSize, plainBuffer.data(), &plainSize);

                        std::string decrypted(reinterpret_cast<char*>(plainBuffer.data()), plainSize);

                        std::cout << "IPgpEngine EncryptStringArmored/DecryptStringArmored round trip: "
                                  << (decrypted == plaintext ? "PASSED" : "FAILED") << std::endl;
                    }
                    else
                    {
                        std::cout << "IPgpEngine::GenerateKeyPair failed, rc=" << rc << std::endl;
                    }

                    pCryptoApiDllLoader->DestroyPgpEngineObject(pPgpEngine);
                }

                // IPgpEngineWrapper round trip through the DLL boundary -- delegates to a real
                // gpg.exe child process instead of CPgpEngine's own RFC 4880 implementation.
                // Unlike IPgpEngine above, this cannot use a self-import (Alice-to-Alice) round
                // trip: gpg's own "--import" reports a key that is already present in the keyring
                // (as it would be here, right after this same instance's own GenerateKeyPair) as
                // "unchanged" rather than "IMPORTED", which importPeerPublicKeyCommon (see
                // Pgp/PgpEngineWrapper.cpp) treats as INVALID_DATA, not success -- verified
                // directly against this machine's gpg.exe while wiring this test up. Uses two
                // separate engine instances (each its own isolated --homedir) instead, matching
                // CCryptoApiTester::RunPgpWrapperEncryptDecryptTest's own Alice/Bob pattern.
                // Skipped gracefully if no local GnuPG install is found (IsGnuPgAvailable), same
                // convention every other GnuPG-backed test in this repo follows.
                CryptoApiNS::IPgpEngineWrapper* pAlice = pCryptoApiDllLoader->GetPgpEngineWrapperObject();
                CryptoApiNS::IPgpEngineWrapper* pBob = pCryptoApiDllLoader->GetPgpEngineWrapperObject();

                if (pAlice && pBob)
                {
                    std::cout << std::endl;

                    if (pAlice->IsGnuPgAvailable())
                    {
                        const char* aliceUserId = "DllRunner Alice <dllrunner-alice@example.com>";
                        const char* alicePassword = "DllRunnerAlicePassword123";
                        const char* bobUserId = "DllRunner Bob <dllrunner-bob@example.com>";
                        const char* bobPassword = "DllRunnerBobPassword123";
                        const char* plaintext = "Hello Bob from DllRunner via IPgpEngineWrapper!";

                        int rc = pAlice->GenerateKeyPair(aliceUserId, static_cast<int>(strlen(aliceUserId)),
                                                        alicePassword, static_cast<int>(strlen(alicePassword)));
                        int rcBob = (rc == CryptoApiNS::NO_ERROR)
                            ? pBob->GenerateKeyPair(bobUserId, static_cast<int>(strlen(bobUserId)),
                                                    bobPassword, static_cast<int>(strlen(bobPassword)))
                            : rc;

                        if (rc == CryptoApiNS::NO_ERROR && rcBob == CryptoApiNS::NO_ERROR)
                        {
                            int alicePubKeySize = 0;
                            pAlice->ExportPublicKeyArmored(0, nullptr, &alicePubKeySize);
                            std::vector<char> alicePubKeyBuffer(alicePubKeySize);
                            pAlice->ExportPublicKeyArmored(alicePubKeySize, alicePubKeyBuffer.data(), &alicePubKeySize);

                            int bobPubKeySize = 0;
                            pBob->ExportPublicKeyArmored(0, nullptr, &bobPubKeySize);
                            std::vector<char> bobPubKeyBuffer(bobPubKeySize);
                            pBob->ExportPublicKeyArmored(bobPubKeySize, bobPubKeyBuffer.data(), &bobPubKeySize);

                            // Alice imports Bob's public key (to encrypt TO Bob); Bob imports
                            // Alice's public key (needed by DecryptStringArmored's own peer
                            // precondition, mirroring CPgpEngine's own contract).
                            pAlice->ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(bobPubKeyBuffer.data()), bobPubKeySize);
                            pBob->ImportPeerPublicKey(reinterpret_cast<const unsigned char*>(alicePubKeyBuffer.data()), alicePubKeySize);

                            int cipherSize = 0;
                            pAlice->EncryptStringArmored(plaintext, static_cast<int>(strlen(plaintext)), 0, nullptr, &cipherSize);

                            std::vector<char> cipherBuffer(cipherSize);
                            pAlice->EncryptStringArmored(plaintext, static_cast<int>(strlen(plaintext)), cipherSize, cipherBuffer.data(), &cipherSize);

                            int plainSize = 0;
                            pBob->DecryptStringArmored(bobPassword, static_cast<int>(strlen(bobPassword)),
                                                        cipherBuffer.data(), cipherSize, 0, nullptr, &plainSize);

                            std::vector<unsigned char> plainBuffer(plainSize);
                            pBob->DecryptStringArmored(bobPassword, static_cast<int>(strlen(bobPassword)),
                                                        cipherBuffer.data(), cipherSize, plainSize, plainBuffer.data(), &plainSize);

                            std::string decrypted(reinterpret_cast<char*>(plainBuffer.data()), plainSize);

                            std::cout << "IPgpEngineWrapper Alice->Bob EncryptStringArmored/DecryptStringArmored round trip: "
                                      << (decrypted == plaintext ? "PASSED" : "FAILED") << std::endl;
                        }
                        else
                        {
                            std::cout << "IPgpEngineWrapper::GenerateKeyPair failed, alice rc=" << rc << " bob rc=" << rcBob << std::endl;
                        }
                    }
                    else
                    {
                        std::cout << "IPgpEngineWrapper: GnuPG not available, skipping round trip." << std::endl;
                    }
                }

                if (pAlice)
                {
                    pCryptoApiDllLoader->DestroyPgpEngineWrapperObject(pAlice);
                }
                if (pBob)
                {
                    pCryptoApiDllLoader->DestroyPgpEngineWrapperObject(pBob);
                }
            }
        }

        delete pCryptoApiDllLoader;
    }
    catch (...)
    {

    }

    return 0;
}

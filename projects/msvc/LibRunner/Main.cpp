#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#include "CryptoApi.h"
#include "CryptoApiTester.h"
#include "Pgp/PgpEngine.h"
#include "Pgp/PgpEngineWrapper.h"

// Linked here instead of via the project's Linker > Input > Additional Dependencies setting;
// the search path (LibBuilder's per-platform output directory) still comes from the project's
// Additional Library Directories, this only supplies the library's name.
#pragma comment(lib, "CryptoAPI_static.lib")

int main()
{
    try
    {
        std::cout << "Hello World!\n";
        std::cout << std::endl;

        CryptoApiNS::CCryptoApi cryptoApi;

        std::cout << "CryptoAPI version: " << cryptoApi.GetVersion() << std::endl;
        std::cout << std::endl;

        // IPgpEngine/IPgpEngineWrapper exercised through their interface pointers even though
        // this is a static link (no DLL boundary to cross) -- proves the new interface layer
        // itself (CPgpEngine : public IPgpEngine / CPgpEngineWrapper : public IPgpEngineWrapper,
        // see Pgp/PgpEngine.h/PgpEngineWrapper.h) compiles and dispatches correctly on its own,
        // independent of DllRunner's DLL-boundary round trip (see DllRunner/Main.cpp). Same
        // Alice-to-Alice self-contained round trip: GenerateKeyPair, export this instance's own
        // public key, re-import it as its own peer, encrypt, decrypt, compare.
        {
            CryptoApiNS::IPgpEngine* pPgpEngine = new CryptoApiNS::CPgpEngine();

            const char* userId = "LibRunner Test <librunner@example.com>";
            const char* password = "LibRunnerTestPassword123";
            const char* plaintext = "Hello from LibRunner via IPgpEngine!";

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

                std::cout << "IPgpEngine (static link) EncryptStringArmored/DecryptStringArmored round trip: "
                          << (decrypted == plaintext ? "PASSED" : "FAILED") << std::endl;
            }
            else
            {
                std::cout << "IPgpEngine::GenerateKeyPair failed, rc=" << rc << std::endl;
            }

            delete pPgpEngine;
        }

        {
            // Two separate engine instances (each its own isolated --homedir), not a self-import:
            // gpg's own "--import" reports a key already present in the keyring (as it would be
            // right after this same instance's own GenerateKeyPair) as "unchanged" rather than
            // "IMPORTED", which importPeerPublicKeyCommon (Pgp/PgpEngineWrapper.cpp) treats as
            // INVALID_DATA, not success -- verified directly against this machine's gpg.exe while
            // wiring this test up. Matches CCryptoApiTester::RunPgpWrapperEncryptDecryptTest's own
            // Alice/Bob pattern; see DllRunner/Main.cpp for the identical DLL-boundary version.
            CryptoApiNS::IPgpEngineWrapper* pAlice = new CryptoApiNS::CPgpEngineWrapper();
            CryptoApiNS::IPgpEngineWrapper* pBob = new CryptoApiNS::CPgpEngineWrapper();

            if (pAlice->IsGnuPgAvailable())
            {
                const char* aliceUserId = "LibRunner Alice <librunner-alice@example.com>";
                const char* alicePassword = "LibRunnerAlicePassword123";
                const char* bobUserId = "LibRunner Bob <librunner-bob@example.com>";
                const char* bobPassword = "LibRunnerBobPassword123";
                const char* plaintext = "Hello Bob from LibRunner via IPgpEngineWrapper!";

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

                    std::cout << "IPgpEngineWrapper (static link) Alice->Bob EncryptStringArmored/DecryptStringArmored round trip: "
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

            delete pAlice;
            delete pBob;
        }

        std::cout << std::endl;

        CryptoApiNS::CCryptoApiTester cryptoApiTester;

        cryptoApiTester.Run();

#if 0
        cryptoApiTester.RunEncryptDecryptFileTest();

        cryptoApiTester.RunEncryptDecryptStringTest();

        cryptoApiTester.RunEncryptDecryptBufferTest();

        cryptoApiTester.RunEncryptDecryptBytesTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderEncryptDecryptFileTest();

        cryptoApiTester.RunMicrosoftProviderEncryptDecryptStringTest();

        cryptoApiTester.RunMicrosoftProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunMicrosoftProviderEncryptDecryptBytesTest();

        cryptoApiTester.RunCryptoPPProviderEncryptDecryptFileTest();

        cryptoApiTester.RunCryptoPPProviderEncryptDecryptStringTest();

        cryptoApiTester.RunCryptoPPProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunCryptoPPProviderEncryptDecryptBytesTest();

        cryptoApiTester.RunBotanProviderEncryptDecryptFileTest();

        cryptoApiTester.RunBotanProviderEncryptDecryptStringTest();

        cryptoApiTester.RunBotanProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunBotanProviderEncryptDecryptBytesTest();

        cryptoApiTester.RunOpenSslProviderEncryptDecryptFileTest();

        cryptoApiTester.RunOpenSslProviderEncryptDecryptStringTest();

        cryptoApiTester.RunOpenSslProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunOpenSslProviderEncryptDecryptBytesTest();

        cryptoApiTester.RunLibgcryptProviderEncryptDecryptFileTest();

        cryptoApiTester.RunLibgcryptProviderEncryptDecryptStringTest();

        cryptoApiTester.RunLibgcryptProviderEncryptDecryptBufferTest();

        cryptoApiTester.RunLibgcryptProviderEncryptDecryptBytesTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderAsymmetricTest();

        cryptoApiTester.RunCryptoPPProviderAsymmetricTest();

        cryptoApiTester.RunBotanProviderAsymmetricTest();

        cryptoApiTester.RunOpenSslProviderAsymmetricTest();

        cryptoApiTester.RunLibgcryptProviderAsymmetricTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderLegacyTest();

        cryptoApiTester.RunCryptoPPProviderLegacyTest();

        cryptoApiTester.RunBotanProviderLegacyTest();

        cryptoApiTester.RunOpenSslProviderLegacyTest();

        cryptoApiTester.RunLibgcryptProviderLegacyTest();
#endif

#if 0
        cryptoApiTester.RunLegacyAlgorithmsTest();  // Uzun surdu
#endif

#if 0
        cryptoApiTester.RunEncryptStringMultilingualTest();

        cryptoApiTester.RunPrimitiveDataTest();

        cryptoApiTester.RunPrimitiveArrayDataTest();

        cryptoApiTester.RunVectorDataTest();

        cryptoApiTester.RunVectorWideStringDataTest();
#endif

#if 0
        cryptoApiTester.RunProviderFactoryTest();

        cryptoApiTester.RunProviderFactoryFileTest();

        cryptoApiTester.RunProviderFactoryStringTest();

        cryptoApiTester.RunProviderFactoryBufferTest();

        cryptoApiTester.RunProviderFactoryBytesTest();
#endif

#if 0
        cryptoApiTester.RunEncryptDecryptFileTestNonBlocking();

        cryptoApiTester.RunEncryptDecryptStringTestNonBlocking();

        cryptoApiTester.RunEncryptDecryptBufferTestNonBlocking();

        cryptoApiTester.RunEncryptDecryptBytesTestNonBlocking();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderAllAlgorithmsTest();

        cryptoApiTester.RunCryptoPPProviderAllAlgorithmsTest();

        cryptoApiTester.RunBotanProviderAllAlgorithmsTest();

        cryptoApiTester.RunOpenSslProviderAllAlgorithmsTest();

        cryptoApiTester.RunLibgcryptProviderAllAlgorithmsTest();
#endif

#if 0
        cryptoApiTester.RunEncodingUtilsTest();

        cryptoApiTester.RunAesConfigurationDemoTest();  // Uzun surdu

        cryptoApiTester.RunPaddingUtilsTest();
#endif

#if 0
        cryptoApiTester.RunEncryptHexBase64CompositionTest();

        cryptoApiTester.RunEncryptFileHexBase64CompositionTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderHashTest();

        cryptoApiTester.RunCryptoPPProviderHashTest();

        cryptoApiTester.RunBotanProviderHashTest();

        cryptoApiTester.RunOpenSslProviderHashTest();

        cryptoApiTester.RunLibgcryptProviderHashTest();
#endif

#if 0
        cryptoApiTester.RunHashAlgorithmsTest();
#endif

#if 0
        cryptoApiTester.RunHashFileTest();

        cryptoApiTester.RunHashStringTest();

        cryptoApiTester.RunHashBufferTest();

        cryptoApiTester.RunHashBytesTest();
#endif

#if 0
        cryptoApiTester.RunProviderFactoryHashTest();

        cryptoApiTester.RunProviderFactoryHashFileTest();

        cryptoApiTester.RunProviderFactoryHashStringTest();

        cryptoApiTester.RunProviderFactoryHashBufferTest();

        cryptoApiTester.RunProviderFactoryHashBytesTest();
#endif

#if 0
        cryptoApiTester.RunHashHexBase64CompositionTest();

        cryptoApiTester.RunHashFileHexBase64CompositionTest();
#endif

#if 0
        cryptoApiTester.RunHashFileTestNonBlocking();

        cryptoApiTester.RunHashStringTestNonBlocking();

        cryptoApiTester.RunHashBufferTestNonBlocking();

        cryptoApiTester.RunHashBytesTestNonBlocking();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderSignatureTest();

        cryptoApiTester.RunCryptoPPProviderSignatureTest();

        cryptoApiTester.RunBotanProviderSignatureTest();        // Uzun surdu

        cryptoApiTester.RunOpenSslProviderSignatureTest();

        cryptoApiTester.RunLibgcryptProviderSignatureTest();

        cryptoApiTester.RunSignatureAlgorithmsTest();
#endif

#if 0
        cryptoApiTester.RunMicrosoftProviderKeyAgreementTest();

        cryptoApiTester.RunCryptoPPProviderKeyAgreementTest();

        cryptoApiTester.RunBotanProviderKeyAgreementTest();

        cryptoApiTester.RunOpenSslProviderKeyAgreementTest();

        cryptoApiTester.RunLibgcryptProviderKeyAgreementTest();

        cryptoApiTester.RunKeyAgreementAlgorithmsTest();
#endif

#if 0
        cryptoApiTester.RunAESTests();  // Uzun surdu
#endif

#if 0
        cryptoApiTester.RunSharedInstanceTest();
#endif

#if 0
        cryptoApiTester.RunRandomAlgorithmsTest();
#endif

#if 1
        cryptoApiTester.RunPgpKeyGenerationTest();

        cryptoApiTester.RunPgpEncryptDecryptTest();

        cryptoApiTester.RunPgpSignVerifyTest();

        cryptoApiTester.RunPgpClearSignTest();

        cryptoApiTester.RunPgpArmorTest();

        cryptoApiTester.RunPgpAliceBobTest();

        cryptoApiTester.RunPgpFileEncryptDecryptTest();

        cryptoApiTester.RunPgpFileSignVerifyTest();

        cryptoApiTester.RunPgpEccFileStreamingTest();

        // TODO: Investigate local gpg-agent socket creation failure in the two GnuPG import tests
        // below. GnuPG reports the public key as imported, then exits with rc=2 because the agent
        // cannot bind its socket under AppData\Local\gnupg ("No such file or directory").
        cryptoApiTester.RunPgpGnuPgInteropTest();

        cryptoApiTester.RunPgpKeyExpirationTest();

        cryptoApiTester.RunPgpGnuPgRevocationInteropTest();

        cryptoApiTester.RunPgpMultiRecipientEncryptDecryptTest();

        cryptoApiTester.RunPgpMixedRecipientEncryptDecryptTest();

        cryptoApiTester.RunPgpMultiRecipientFileEncryptDecryptTest();

        cryptoApiTester.RunPgpGnuPgMultiRecipientInteropTest();

        cryptoApiTester.RunPgpGnuPgMixedAlgorithmRecipientInteropTest();

        cryptoApiTester.RunPgpEd25519KeyGenerationTest();

        cryptoApiTester.RunPgpEd25519EncryptDecryptTest();

        cryptoApiTester.RunPgpEd25519SignVerifyTest();

        cryptoApiTester.RunPgpEd25519ClearSignTest();

        cryptoApiTester.RunPgpGnuPgEd25519InteropTest();

        cryptoApiTester.RunPgpEd25519KeyExpirationTest();

        cryptoApiTester.RunPgpGnuPgEd25519RevocationInteropTest();

        cryptoApiTester.RunPgpEncryptFileCompressedZipTest();

        cryptoApiTester.RunPgpEncryptFileCompressedZlibTest();

        cryptoApiTester.RunPgpEncryptFileCompressedEmptyFileTest();

        cryptoApiTester.RunPgpEncryptFileCompressedLargeFileTest();

        cryptoApiTester.RunPgpEncryptFileCompressedCancellationTest();

        cryptoApiTester.RunPgpEncryptFileCompressedCorruptionTest();

        cryptoApiTester.RunPgpGnuPgBzip2InteropTest();

        cryptoApiTester.RunPgpGnuPgBzip2DecryptBufferInteropTest();

        cryptoApiTester.RunPgpGnuPgPartialBodyLengthInteropTest();

        cryptoApiTester.RunPgpInspectionEncryptedMessageTest();

        cryptoApiTester.RunPgpInspectionMultiRecipientTest();

        cryptoApiTester.RunPgpInspectionSignatureTest();

        cryptoApiTester.RunPgpGnuPgInspectionInteropTest();
#endif

#if 0
        cryptoApiTester.RunPgpWrapperAvailabilityTest();

        cryptoApiTester.RunPgpWrapperKeyGenerationTest();

        cryptoApiTester.RunPgpWrapperEncryptDecryptTest();  // FAILED, PASSED

        cryptoApiTester.RunPgpWrapperSignVerifyTest();

        cryptoApiTester.RunPgpWrapperClearSignTest();

        cryptoApiTester.RunPgpWrapperAliceBobTest();

        cryptoApiTester.RunPgpWrapperFileEncryptDecryptTest();

        cryptoApiTester.RunPgpWrapperFileSignVerifyTest();

        cryptoApiTester.RunPgpWrapperKeyExpirationTest();

        cryptoApiTester.RunPgpWrapperKeyRevocationTest();

        cryptoApiTester.RunPgpWrapperMultiRecipientEncryptTest();

        cryptoApiTester.RunPgpWrapperEccKeyGenerationTest();

        cryptoApiTester.RunPgpWrapperSymmetricEncryptDecryptTest();

        cryptoApiTester.RunPgpWrapperKeyringListDeleteTest();

        cryptoApiTester.RunPgpWrapperCompressionAlgorithmTest();

        cryptoApiTester.RunPgpWrapperInspectionEncryptedMessageTest();

        cryptoApiTester.RunPgpWrapperInspectionMultiRecipientTest();

        cryptoApiTester.RunPgpWrapperInspectionSymmetricTest();

        cryptoApiTester.RunPgpWrapperInspectionSignatureTest();
#endif
    }
    catch (...)
    {

    }

    return 0;
}

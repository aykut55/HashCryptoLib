#include "ScriptEngineTester.h"
#include "Definitions/Definitions.h"
#include "LuaScript/LuaScriptEngineSol.h"
#include "LuaScript/LuaScriptEngineLuaBridge.h"
#include "LuaScript/LuaScriptEngineLuaBridgeLegacy.h"

#include <exception>
#include <iostream>

namespace CryptoApiNS
{

CScriptEngineTester::~CScriptEngineTester()
{
}
// -----------------------------------------------------------------------------

CScriptEngineTester::CScriptEngineTester()
{
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptHashTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local api = CryptoApi.new()\n"
            "local digestA = api:ComputeHashString(\"The quick brown fox jumps over the lazy dog\")\n"
            "local digestB = api:ComputeHashString(\"The quick brown fox jumps over the lazy dog\")\n"
            "ok = (#digestA == api:GetHashSize()) and (#digestA == #digestB)\n"
            "for i = 1, #digestA do\n"
            "    if digestA[i] ~= digestB[i] then ok = false end\n"
            "end\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptHashTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptHashTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptHashTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptHashTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptEncryptDecryptTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local api = CryptoApi.new()\n"
            "local password = \"s3cr3t-lua-password\"\n"
            "local plaintext = \"Hello from Lua via sol2!\"\n"
            "local ciphertext = api:EncryptString(password, plaintext)\n"
            "local decrypted = api:DecryptString(password, ciphertext)\n"
            "ok = (decrypted == plaintext)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptEncryptDecryptTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptEncryptDecryptTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptEncryptDecryptTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptEncryptDecryptTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptAsymmetricTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local api = CryptoApi.new()\n"
            "api:GenerateAsymmetricKeyPair()\n"
            "local plaintext = \"RSA round trip via Lua\"\n"
            "local inputBytes = ToBytes(plaintext)\n"
            "local ciphertext = api:EncryptWithPublicKey(inputBytes)\n"
            "local decryptedBytes = api:DecryptWithPrivateKey(ciphertext)\n"
            "local chars = {}\n"
            "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
            "ok = (table.concat(chars) == plaintext) and (#ciphertext == api:GetAsymmetricCiphertextSize())\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptAsymmetricTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptAsymmetricTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptAsymmetricTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptAsymmetricTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptSignatureTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local api = CryptoApi.new()\n"
            "api:GenerateSignatureKeyPair()\n"
            "local message = \"Sign this message from Lua\"\n"
            "local inputBytes = ToBytes(message)\n"
            "local signature = api:SignBuffer(inputBytes)\n"
            "ok = api:VerifyBuffer(inputBytes, signature) and (#signature == api:GetSignatureSize())\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptSignatureTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptSignatureTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptSignatureTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptSignatureTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptKeyAgreementTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local alice = CryptoApi.new()\n"
            "local bob = CryptoApi.new()\n"
            "alice:GenerateKeyAgreementKeyPair()\n"
            "bob:GenerateKeyAgreementKeyPair()\n"
            "local alicePublic = alice:ExportKeyAgreementPublicKey()\n"
            "local bobPublic = bob:ExportKeyAgreementPublicKey()\n"
            "local aliceSecret = alice:DeriveSharedSecret(bobPublic)\n"
            "local bobSecret = bob:DeriveSharedSecret(alicePublic)\n"
            "ok = (#aliceSecret == #bobSecret) and (#aliceSecret == alice:GetSharedSecretSize())\n"
            "for i = 1, #aliceSecret do\n"
            "    if aliceSecret[i] ~= bobSecret[i] then ok = false end\n"
            "end\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptKeyAgreementTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptKeyAgreementTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptKeyAgreementTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptKeyAgreementTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptRandomTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local api = CryptoApi.new()\n"
            "local randomBytes = api:GenerateRandomBytes(32)\n"
            "ok = (#randomBytes == 32)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptRandomTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptRandomTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptRandomTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptRandomTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptPgpKeyGenerationTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local pgp = PgpEngine.new()\n"
            "pgp:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-lua-pw\")\n"
            "local keyId = pgp:GetKeyId()\n"
            "ok = (#keyId == 16)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptPgpKeyGenerationTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptPgpKeyGenerationTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptPgpKeyGenerationTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptPgpKeyGenerationTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptPgpEncryptDecryptTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local alice = PgpEngine.new()\n"
            "local bob = PgpEngine.new()\n"
            "alice:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-lua-pw\")\n"
            "bob:GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-lua-pw\")\n"
            "alice:ImportPeerPublicKey(bob:ExportPublicKeyArmored())\n"
            "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
            "local plaintext = \"Hello Bob, this message was encrypted entirely from Lua.\"\n"
            "local ciphertext = alice:EncryptStringArmored(plaintext)\n"
            "local decryptedBytes = bob:DecryptStringArmored(\"bob-lua-pw\", ciphertext)\n"
            "local chars = {}\n"
            "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
            "ok = (table.concat(chars) == plaintext)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptPgpEncryptDecryptTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptPgpEncryptDecryptTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptPgpEncryptDecryptTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptPgpEncryptDecryptTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptPgpSignVerifyTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local alice = PgpEngine.new()\n"
            "local bob = PgpEngine.new()\n"
            "alice:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-lua-pw\")\n"
            "bob:GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-lua-pw\")\n"
            "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
            "local message = \"This clear-signed message comes from Lua.\"\n"
            "local signed = alice:ClearSignString(\"alice-lua-pw\", message)\n"
            "ok = bob:VerifyClearSignedString(signed)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptPgpSignVerifyTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptPgpSignVerifyTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptPgpSignVerifyTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptPgpSignVerifyTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaScriptPgpWrapperAvailabilityTest(void)
{
    try
    {
        CLuaScriptEngineSol luaEngine;
        const char* script =
            "local wrapper = PgpEngineWrapper.new()\n"
            "gnupgAvailable = wrapper:IsGnuPgAvailable()\n"
            "ok = true\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaScriptPgpWrapperAvailabilityTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaScriptPgpWrapperAvailabilityTest: PASSED (GnuPG available=" << (luaEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaScriptPgpWrapperAvailabilityTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaScriptPgpWrapperAvailabilityTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptHashTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "local digestA = api:ComputeHashString(\"The quick brown fox jumps over the lazy dog\")\n"
            "local digestB = api:ComputeHashString(\"The quick brown fox jumps over the lazy dog\")\n"
            "ok = (#digestA == api:GetHashSize()) and (#digestA == #digestB)\n"
            "for i = 1, #digestA do\n"
            "    if digestA[i] ~= digestB[i] then ok = false end\n"
            "end\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptHashTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptHashTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptHashTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptHashTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptEncryptDecryptTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "local password = \"s3cr3t-luabridge-password\"\n"
            "local plaintext = \"Hello from Lua via LuaBridge3!\"\n"
            "local ciphertext = api:EncryptString(password, plaintext)\n"
            "local decrypted = api:DecryptString(password, ciphertext)\n"
            "ok = (decrypted == plaintext)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptEncryptDecryptTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptEncryptDecryptTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptEncryptDecryptTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptEncryptDecryptTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptAsymmetricTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "api:GenerateAsymmetricKeyPair()\n"
            "local plaintext = \"RSA round trip via LuaBridge3\"\n"
            "local inputBytes = {}\n"
            "for i = 1, #plaintext do inputBytes[i] = string.byte(plaintext, i) end\n"
            "local ciphertext = api:EncryptWithPublicKey(inputBytes)\n"
            "local decryptedBytes = api:DecryptWithPrivateKey(ciphertext)\n"
            "local chars = {}\n"
            "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
            "ok = (table.concat(chars) == plaintext) and (#ciphertext == api:GetAsymmetricCiphertextSize())\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptAsymmetricTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptAsymmetricTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptAsymmetricTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptAsymmetricTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptSignatureTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "api:GenerateSignatureKeyPair()\n"
            "local message = \"Sign this message from LuaBridge3\"\n"
            "local inputBytes = {}\n"
            "for i = 1, #message do inputBytes[i] = string.byte(message, i) end\n"
            "local signature = api:SignBuffer(inputBytes)\n"
            "ok = api:VerifyBuffer(inputBytes, signature) and (#signature == api:GetSignatureSize())\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptSignatureTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptSignatureTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptSignatureTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptSignatureTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptKeyAgreementTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local alice = CryptoApi()\n"
            "local bob = CryptoApi()\n"
            "alice:GenerateKeyAgreementKeyPair()\n"
            "bob:GenerateKeyAgreementKeyPair()\n"
            "local alicePublic = alice:ExportKeyAgreementPublicKey()\n"
            "local bobPublic = bob:ExportKeyAgreementPublicKey()\n"
            "local aliceSecret = alice:DeriveSharedSecret(bobPublic)\n"
            "local bobSecret = bob:DeriveSharedSecret(alicePublic)\n"
            "ok = (#aliceSecret == #bobSecret) and (#aliceSecret == alice:GetSharedSecretSize())\n"
            "for i = 1, #aliceSecret do\n"
            "    if aliceSecret[i] ~= bobSecret[i] then ok = false end\n"
            "end\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptKeyAgreementTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptKeyAgreementTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptKeyAgreementTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptKeyAgreementTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptRandomTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "local randomBytes = api:GenerateRandomBytes(32)\n"
            "ok = (#randomBytes == 32)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptRandomTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptRandomTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptRandomTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptRandomTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptPgpKeyGenerationTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local pgp = PgpEngine()\n"
            "pgp:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-luabridge-pw\")\n"
            "local keyId = pgp:GetKeyId()\n"
            "ok = (#keyId == 16)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptPgpKeyGenerationTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptPgpKeyGenerationTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptPgpKeyGenerationTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptPgpKeyGenerationTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptPgpEncryptDecryptTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local alice = PgpEngine()\n"
            "local bob = PgpEngine()\n"
            "alice:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-luabridge-pw\")\n"
            "bob:GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-luabridge-pw\")\n"
            "alice:ImportPeerPublicKey(bob:ExportPublicKeyArmored())\n"
            "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
            "local plaintext = \"Hello Bob, this message was encrypted entirely from LuaBridge3.\"\n"
            "local ciphertext = alice:EncryptStringArmored(plaintext)\n"
            "local decryptedBytes = bob:DecryptStringArmored(\"bob-luabridge-pw\", ciphertext)\n"
            "local chars = {}\n"
            "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
            "ok = (table.concat(chars) == plaintext)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptPgpEncryptDecryptTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptPgpEncryptDecryptTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptPgpEncryptDecryptTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptPgpEncryptDecryptTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptPgpSignVerifyTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local alice = PgpEngine()\n"
            "local bob = PgpEngine()\n"
            "alice:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-luabridge-pw\")\n"
            "bob:GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-luabridge-pw\")\n"
            "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
            "local message = \"This clear-signed message comes from LuaBridge3.\"\n"
            "local signed = alice:ClearSignString(\"alice-luabridge-pw\", message)\n"
            "ok = bob:VerifyClearSignedString(signed)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptPgpSignVerifyTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptPgpSignVerifyTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptPgpSignVerifyTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptPgpSignVerifyTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeScriptPgpWrapperAvailabilityTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridge luaEngine;
        const char* script =
            "local wrapper = PgpEngineWrapper()\n"
            "gnupgAvailable = wrapper:IsGnuPgAvailable()\n"
            "ok = true\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeScriptPgpWrapperAvailabilityTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeScriptPgpWrapperAvailabilityTest: PASSED (GnuPG available=" << (luaEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeScriptPgpWrapperAvailabilityTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeScriptPgpWrapperAvailabilityTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptHashTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "local digestA = api:ComputeHashString(\"The quick brown fox jumps over the lazy dog\")\n"
            "local digestB = api:ComputeHashString(\"The quick brown fox jumps over the lazy dog\")\n"
            "ok = (#digestA == api:GetHashSize()) and (#digestA == #digestB)\n"
            "for i = 1, #digestA do\n"
            "    if digestA[i] ~= digestB[i] then ok = false end\n"
            "end\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptHashTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptHashTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptHashTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptHashTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptEncryptDecryptTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "local password = \"s3cr3t-luabridge-legacy-password\"\n"
            "local plaintext = \"Hello from Lua via LuaBridge 2.10!\"\n"
            "local ciphertext = api:EncryptString(password, plaintext)\n"
            "local decrypted = api:DecryptString(password, ciphertext)\n"
            "ok = (decrypted == plaintext)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptEncryptDecryptTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptEncryptDecryptTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptEncryptDecryptTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptEncryptDecryptTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptAsymmetricTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "api:GenerateAsymmetricKeyPair()\n"
            "local plaintext = \"RSA round trip via LuaBridge 2.10\"\n"
            "local inputBytes = {}\n"
            "for i = 1, #plaintext do inputBytes[i] = string.byte(plaintext, i) end\n"
            "local ciphertext = api:EncryptWithPublicKey(inputBytes)\n"
            "local decryptedBytes = api:DecryptWithPrivateKey(ciphertext)\n"
            "local chars = {}\n"
            "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
            "ok = (table.concat(chars) == plaintext) and (#ciphertext == api:GetAsymmetricCiphertextSize())\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptAsymmetricTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptAsymmetricTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptAsymmetricTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptAsymmetricTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptSignatureTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "api:GenerateSignatureKeyPair()\n"
            "local message = \"Sign this message from LuaBridge 2.10\"\n"
            "local inputBytes = {}\n"
            "for i = 1, #message do inputBytes[i] = string.byte(message, i) end\n"
            "local signature = api:SignBuffer(inputBytes)\n"
            "ok = api:VerifyBuffer(inputBytes, signature) and (#signature == api:GetSignatureSize())\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptSignatureTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptSignatureTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptSignatureTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptSignatureTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptKeyAgreementTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local alice = CryptoApi()\n"
            "local bob = CryptoApi()\n"
            "alice:GenerateKeyAgreementKeyPair()\n"
            "bob:GenerateKeyAgreementKeyPair()\n"
            "local alicePublic = alice:ExportKeyAgreementPublicKey()\n"
            "local bobPublic = bob:ExportKeyAgreementPublicKey()\n"
            "local aliceSecret = alice:DeriveSharedSecret(bobPublic)\n"
            "local bobSecret = bob:DeriveSharedSecret(alicePublic)\n"
            "ok = (#aliceSecret == #bobSecret) and (#aliceSecret == alice:GetSharedSecretSize())\n"
            "for i = 1, #aliceSecret do\n"
            "    if aliceSecret[i] ~= bobSecret[i] then ok = false end\n"
            "end\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptKeyAgreementTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptKeyAgreementTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptKeyAgreementTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptKeyAgreementTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptRandomTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local api = CryptoApi()\n"
            "local randomBytes = api:GenerateRandomBytes(32)\n"
            "ok = (#randomBytes == 32)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptRandomTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptRandomTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptRandomTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptRandomTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptPgpKeyGenerationTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local pgp = PgpEngine()\n"
            "pgp:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-luabridge-legacy-pw\")\n"
            "local keyId = pgp:GetKeyId()\n"
            "ok = (#keyId == 16)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptPgpKeyGenerationTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptPgpKeyGenerationTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptPgpKeyGenerationTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptPgpKeyGenerationTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptPgpEncryptDecryptTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local alice = PgpEngine()\n"
            "local bob = PgpEngine()\n"
            "alice:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-luabridge-legacy-pw\")\n"
            "bob:GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-luabridge-legacy-pw\")\n"
            "alice:ImportPeerPublicKey(bob:ExportPublicKeyArmored())\n"
            "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
            "local plaintext = \"Hello Bob, this message was encrypted entirely from LuaBridge 2.10.\"\n"
            "local ciphertext = alice:EncryptStringArmored(plaintext)\n"
            "local decryptedBytes = bob:DecryptStringArmored(\"bob-luabridge-legacy-pw\", ciphertext)\n"
            "local chars = {}\n"
            "for i = 1, #decryptedBytes do chars[i] = string.char(decryptedBytes[i]) end\n"
            "ok = (table.concat(chars) == plaintext)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptPgpEncryptDecryptTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptPgpEncryptDecryptTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptPgpEncryptDecryptTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptPgpEncryptDecryptTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptPgpSignVerifyTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local alice = PgpEngine()\n"
            "local bob = PgpEngine()\n"
            "alice:GenerateKeyPair(\"Alice <alice@example.com>\", \"alice-luabridge-legacy-pw\")\n"
            "bob:GenerateKeyPair(\"Bob <bob@example.com>\", \"bob-luabridge-legacy-pw\")\n"
            "bob:ImportPeerPublicKey(alice:ExportPublicKeyArmored())\n"
            "local message = \"This clear-signed message comes from LuaBridge 2.10.\"\n"
            "local signed = alice:ClearSignString(\"alice-luabridge-legacy-pw\", message)\n"
            "ok = bob:VerifyClearSignedString(signed)\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptPgpSignVerifyTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptPgpSignVerifyTest: PASSED" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptPgpSignVerifyTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptPgpSignVerifyTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CScriptEngineTester::RunLuaBridgeLegacyScriptPgpWrapperAvailabilityTest(void)
{
    try
    {
        CLuaScriptEngineLuaBridgeLegacy luaEngine;
        const char* script =
            "local wrapper = PgpEngineWrapper()\n"
            "gnupgAvailable = wrapper:IsGnuPgAvailable()\n"
            "ok = true\n";

        luaEngine.RunString(script);
        if (!luaEngine.GetGlobalBool("ok"))
        {
            std::cout << "RunLuaBridgeLegacyScriptPgpWrapperAvailabilityTest: FAILED" << std::endl;
            return UNEXPECTED_ERROR;
        }

        std::cout << "RunLuaBridgeLegacyScriptPgpWrapperAvailabilityTest: PASSED (GnuPG available=" << (luaEngine.GetGlobalBool("gnupgAvailable") ? "true" : "false") << ")" << std::endl;
        return NO_ERROR;
    }
    catch (const std::exception& ex)
    {
        std::cout << "RunLuaBridgeLegacyScriptPgpWrapperAvailabilityTest: FAILED exception " << ex.what() << std::endl;
        return UNEXPECTED_ERROR;
    }
    catch (...)
    {
        std::cout << "RunLuaBridgeLegacyScriptPgpWrapperAvailabilityTest: FAILED unknown exception" << std::endl;
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

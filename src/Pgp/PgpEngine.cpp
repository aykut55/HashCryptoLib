#include "PgpEngine.h"
#include "Definitions/Definitions.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#ifdef EncryptFile
#undef EncryptFile
#endif
#ifdef DecryptFile
#undef DecryptFile
#endif

#include "cryptopp890/aes.h"
#include "cryptopp890/filters.h"
#include "cryptopp890/integer.h"
#include "cryptopp890/modes.h"
#include "cryptopp890/osrng.h"
#include "cryptopp890/rsa.h"
#include "cryptopp890/sha.h"
#include "cryptopp890/zdeflate.h"
#include "cryptopp890/zinflate.h"
#include "cryptopp890/zlib.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace CryptoApiNS
{

// RFC 4880 packet tags this engine reads/writes. Packet headers can be either RFC 4880 format
// (produced by writePacket below) or old format (only accepted, never produced -- see
// readPacketHeader's own comment for why real-world producers like GnuPG still use it).
namespace
{
    const unsigned char PGP_TAG_PKESK           = 1;
    const unsigned char PGP_TAG_SIGNATURE       = 2;
    const unsigned char PGP_TAG_SECRET_KEY      = 5;
    const unsigned char PGP_TAG_PUBLIC_KEY      = 6;
    const unsigned char PGP_TAG_SECRET_SUBKEY   = 7;
    const unsigned char PGP_TAG_COMPRESSED_DATA = 8;
    const unsigned char PGP_TAG_LITERAL_DATA    = 11;
    const unsigned char PGP_TAG_PUBLIC_SUBKEY   = 14;
    const unsigned char PGP_TAG_SEIP            = 18;
}

struct CPgpEngine::Impl
{
    int rsaKeyBits;
    bool ownKeyGenerated;
    CryptoPP::RSA::PrivateKey ownMasterPrivateKey;
    CryptoPP::RSA::PublicKey  ownMasterPublicKey;
    CryptoPP::RSA::PrivateKey ownSubkeyPrivateKey;
    CryptoPP::RSA::PublicKey  ownSubkeyPublicKey;
    unsigned char ownMasterKeyId[8];
    unsigned char ownSubkeyKeyId[8];
    unsigned char passwordCheckHash[32];
    std::string ownPublicKeyArmored;
    std::string ownSecretKeyArmored;

    bool peerKeyImported;
    CryptoPP::RSA::PublicKey peerMasterPublicKey;
    CryptoPP::RSA::PublicKey peerSubkeyPublicKey;
    unsigned char peerMasterKeyId[8];
    unsigned char peerSubkeyKeyId[8];

    Impl() : rsaKeyBits(2048), ownKeyGenerated(false), peerKeyImported(false)
    {
        std::memset(ownMasterKeyId, 0, 8);
        std::memset(ownSubkeyKeyId, 0, 8);
        std::memset(passwordCheckHash, 0, 32);
        std::memset(peerMasterKeyId, 0, 8);
        std::memset(peerSubkeyKeyId, 0, 8);
    }
};

namespace
{

// ================================================================================================
// UTF-8 file path + raw Win32 file I/O plumbing for the streaming EncryptFile/DecryptFile/
// SignFile/VerifyFile methods below -- same conventions CryptoApi.cpp's own EncryptFile/
// DecryptFile use (UTF-8 path, chunked ReadFile/WriteFile, best-effort cleanup on failure).
// ================================================================================================

// 1 MiB streaming chunk size for the File-based methods below -- chosen independently of
// CryptoApi.cpp's own (differently-named) FILE_CHUNK_SIZE constant, not shared with it.
const std::size_t PGP_FILE_CHUNK_SIZE = 1048576;

bool convertUtf8PathToWide(const char* utf8Path, std::wstring& widePath)
{
    try
    {
        if (utf8Path == nullptr)
        {
            return false;
        }

        const int widePathSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Path, -1, nullptr, 0);
        if (widePathSize <= 0)
        {
            return false;
        }

        std::vector<wchar_t> widePathBuffer(static_cast<std::size_t>(widePathSize));
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Path, -1, &widePathBuffer[0], widePathSize) <= 0)
        {
            return false;
        }

        widePath.assign(&widePathBuffer[0]);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool readFileExact(HANDLE fileHandle, unsigned char* buffer, const DWORD size)
{
    try
    {
        DWORD bytesReadTotal = 0;
        while (bytesReadTotal < size)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(fileHandle, buffer + bytesReadTotal, size - bytesReadTotal, &bytesRead, nullptr) || bytesRead == 0)
            {
                return false;
            }
            bytesReadTotal += bytesRead;
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool writeFileExact(HANDLE fileHandle, const unsigned char* buffer, const DWORD size)
{
    try
    {
        DWORD bytesWrittenTotal = 0;
        while (bytesWrittenTotal < size)
        {
            DWORD bytesWritten = 0;
            if (!WriteFile(fileHandle, buffer + bytesWrittenTotal, size - bytesWrittenTotal, &bytesWritten, nullptr) || bytesWritten == 0)
            {
                return false;
            }
            bytesWrittenTotal += bytesWritten;
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// Byte/integer plumbing -- big-endian fields, RFC 4880 MPI encoding (section 3.2), new-format
// packet/subpacket length encoding (section 4.2.2 / 5.2.3.1).
// ================================================================================================

void appendAll(std::vector<unsigned char>& out, const std::vector<unsigned char>& in)
{
    out.insert(out.end(), in.begin(), in.end());
}
// -----------------------------------------------------------------------------

void appendBigEndian16(std::vector<unsigned char>& out, const std::uint16_t value)
{
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    out.push_back(static_cast<unsigned char>(value & 0xFF));
}
// -----------------------------------------------------------------------------

void appendBigEndian32(std::vector<unsigned char>& out, const std::uint32_t value)
{
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xFF));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xFF));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    out.push_back(static_cast<unsigned char>(value & 0xFF));
}
// -----------------------------------------------------------------------------

std::size_t readBigEndian16(const std::vector<unsigned char>& data, const std::size_t pos)
{
    return (static_cast<std::size_t>(data[pos]) << 8) | static_cast<std::size_t>(data[pos + 1]);
}
// -----------------------------------------------------------------------------

void appendNewFormatLength(std::vector<unsigned char>& out, const std::size_t length)
{
    if (length < 192)
    {
        out.push_back(static_cast<unsigned char>(length));
    }
    else if (length < 8384)
    {
        const std::size_t adjusted = length - 192;
        out.push_back(static_cast<unsigned char>((adjusted >> 8) + 192));
        out.push_back(static_cast<unsigned char>(adjusted & 0xFF));
    }
    else
    {
        out.push_back(0xFF);
        appendBigEndian32(out, static_cast<std::uint32_t>(length));
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> writePacket(const unsigned char tag, const std::vector<unsigned char>& body)
{
    std::vector<unsigned char> out;
    out.push_back(static_cast<unsigned char>(0xC0 | tag));
    appendNewFormatLength(out, body.size());
    appendAll(out, body);
    return out;
}
// -----------------------------------------------------------------------------

// Writers in this file (writePacket below) only ever produce new-format headers, but real-world
// OpenPGP producers (confirmed against GnuPG 2.5.21's own output) still emit OLD-format headers
// (RFC 4880 section 4.2.1) for packets whose tag fits in 4 bits -- e.g. GnuPG encodes a PKESK
// (tag 1) with an old-format 3-byte header but a SEIP (tag 18, too large for old format's 4-bit
// tag field) with a new-format header, in the very same message. GnuPG also encodes the
// Compressed Data packet nested inside a decrypted SEIP body with an old-format "indeterminate
// length" header (length-type 3, RFC 4880 section 4.2.1) -- no length field at all, the body
// simply runs to the end of the enclosing context. dataEnd supplies that context boundary (the
// caller's own end-of-buffer, or an inner boundary like the byte just before the MDC trailer);
// it defaults to data.size() for ordinary top-level parsing. New-format partial-body lengths
// (first length byte 224-254) are still not supported -- out of scope for this v1 engine.
bool readPacketHeader(const std::vector<unsigned char>& data, std::size_t& pos, unsigned char& tag, std::size_t& bodyLength, const std::size_t dataEnd = static_cast<std::size_t>(-1))
{
    try
    {
        const std::size_t effectiveEnd = (dataEnd == static_cast<std::size_t>(-1)) ? data.size() : dataEnd;
        if (pos >= data.size() || (data[pos] & 0x80) == 0)
        {
            return false;
        }

        const unsigned char first = data[pos];
        pos += 1;

        if ((first & 0x40) != 0)
        {
            // New format (RFC 4880 section 4.2.2).
            tag = first & 0x3F;
            if (pos >= data.size())
            {
                return false;
            }

            const unsigned char lenFirst = data[pos];
            if (lenFirst < 192)
            {
                bodyLength = lenFirst;
                pos += 1;
            }
            else if (lenFirst < 224)
            {
                if (pos + 1 >= data.size())
                {
                    return false;
                }
                bodyLength = (static_cast<std::size_t>(lenFirst - 192) << 8) + data[pos + 1] + 192;
                pos += 2;
            }
            else if (lenFirst == 255)
            {
                if (pos + 4 >= data.size())
                {
                    return false;
                }
                bodyLength = (static_cast<std::size_t>(data[pos + 1]) << 24) | (static_cast<std::size_t>(data[pos + 2]) << 16) |
                             (static_cast<std::size_t>(data[pos + 3]) << 8)  |  static_cast<std::size_t>(data[pos + 4]);
                pos += 5;
            }
            else
            {
                return false;
            }
        }
        else
        {
            // Old format (RFC 4880 section 4.2.1): tag is only 4 bits, length-type is 2 bits.
            tag = (first >> 2) & 0x0F;
            const unsigned char lengthType = first & 0x03;
            if (lengthType == 0)
            {
                if (pos >= data.size())
                {
                    return false;
                }
                bodyLength = data[pos];
                pos += 1;
            }
            else if (lengthType == 1)
            {
                if (pos + 1 >= data.size())
                {
                    return false;
                }
                bodyLength = (static_cast<std::size_t>(data[pos]) << 8) | data[pos + 1];
                pos += 2;
            }
            else if (lengthType == 2)
            {
                if (pos + 3 >= data.size())
                {
                    return false;
                }
                bodyLength = (static_cast<std::size_t>(data[pos]) << 24) | (static_cast<std::size_t>(data[pos + 1]) << 16) |
                             (static_cast<std::size_t>(data[pos + 2]) << 8) |  static_cast<std::size_t>(data[pos + 3]);
                pos += 4;
            }
            else
            {
                // Indeterminate length: body runs to the end of the enclosing context.
                if (pos > effectiveEnd)
                {
                    return false;
                }
                bodyLength = effectiveEnd - pos;
            }
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

void appendSubpacket(std::vector<unsigned char>& out, const unsigned char type, const std::vector<unsigned char>& body)
{
    appendNewFormatLength(out, body.size() + 1);
    out.push_back(type);
    appendAll(out, body);
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> encodeMpi(const CryptoPP::Integer& value)
{
    try
    {
        const std::size_t bitCount = static_cast<std::size_t>(value.BitCount());
        const std::size_t byteCount = (bitCount + 7) / 8;

        std::vector<unsigned char> out;
        appendBigEndian16(out, static_cast<std::uint16_t>(bitCount));
        if (byteCount > 0)
        {
            std::vector<unsigned char> bytes(byteCount);
            value.Encode(bytes.data(), byteCount);
            appendAll(out, bytes);
        }
        return out;
    }
    catch (...)
    {
        return std::vector<unsigned char>();
    }
}
// -----------------------------------------------------------------------------

bool readMpi(const std::vector<unsigned char>& data, std::size_t& pos, CryptoPP::Integer& out)
{
    try
    {
        if (pos + 2 > data.size())
        {
            return false;
        }
        const std::size_t bitLength = readBigEndian16(data, pos);
        pos += 2;
        const std::size_t byteLength = (bitLength + 7) / 8;
        if (pos + byteLength > data.size())
        {
            return false;
        }
        out = CryptoPP::Integer(&data[pos], byteLength);
        pos += byteLength;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::size_t rsaModulusByteLength(const CryptoPP::Integer& modulus)
{
    return static_cast<std::size_t>(modulus.MinEncodedSize());
}
// -----------------------------------------------------------------------------

// ================================================================================================
// CRC24 (RFC 4880 section 6.1) + Radix-64 base64 + ASCII armor (section 6.2).
// ================================================================================================

std::uint32_t crc24(const std::vector<unsigned char>& data)
{
    std::uint32_t crc = 0xB704CEUL;
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        crc ^= (static_cast<std::uint32_t>(data[i]) << 16);
        for (int bit = 0; bit < 8; ++bit)
        {
            crc <<= 1;
            if (crc & 0x1000000UL)
            {
                crc ^= 0x1864CFBUL;
            }
        }
    }
    return crc & 0xFFFFFFUL;
}
// -----------------------------------------------------------------------------

std::string base64Encode(const std::vector<unsigned char>& data)
{
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    while (i + 3 <= data.size())
    {
        const unsigned int n = (static_cast<unsigned int>(data[i]) << 16) | (static_cast<unsigned int>(data[i + 1]) << 8) | data[i + 2];
        out += alphabet[(n >> 18) & 0x3F];
        out += alphabet[(n >> 12) & 0x3F];
        out += alphabet[(n >> 6) & 0x3F];
        out += alphabet[n & 0x3F];
        i += 3;
    }
    const std::size_t rem = data.size() - i;
    if (rem == 1)
    {
        const unsigned int n = static_cast<unsigned int>(data[i]) << 16;
        out += alphabet[(n >> 18) & 0x3F];
        out += alphabet[(n >> 12) & 0x3F];
        out += "==";
    }
    else if (rem == 2)
    {
        const unsigned int n = (static_cast<unsigned int>(data[i]) << 16) | (static_cast<unsigned int>(data[i + 1]) << 8);
        out += alphabet[(n >> 18) & 0x3F];
        out += alphabet[(n >> 12) & 0x3F];
        out += alphabet[(n >> 6) & 0x3F];
        out += "=";
    }
    return out;
}
// -----------------------------------------------------------------------------

bool base64Decode(const std::string& text, std::vector<unsigned char>& out)
{
    try
    {
        static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int lookup[256];
        for (int i = 0; i < 256; ++i)
        {
            lookup[i] = -1;
        }
        for (int i = 0; i < 64; ++i)
        {
            lookup[static_cast<unsigned char>(alphabet[i])] = i;
        }

        std::vector<int> digits;
        digits.reserve(text.size());
        for (std::size_t i = 0; i < text.size(); ++i)
        {
            const unsigned char c = static_cast<unsigned char>(text[i]);
            if (c == '=')
            {
                break;
            }
            const int v = lookup[c];
            if (v >= 0)
            {
                digits.push_back(v);
            }
        }

        out.clear();
        std::size_t i = 0;
        while (i + 4 <= digits.size())
        {
            const unsigned int n = (static_cast<unsigned int>(digits[i]) << 18) | (static_cast<unsigned int>(digits[i + 1]) << 12) |
                                   (static_cast<unsigned int>(digits[i + 2]) << 6) | static_cast<unsigned int>(digits[i + 3]);
            out.push_back(static_cast<unsigned char>((n >> 16) & 0xFF));
            out.push_back(static_cast<unsigned char>((n >> 8) & 0xFF));
            out.push_back(static_cast<unsigned char>(n & 0xFF));
            i += 4;
        }
        const std::size_t rem = digits.size() - i;
        if (rem == 2)
        {
            const unsigned int n = (static_cast<unsigned int>(digits[i]) << 18) | (static_cast<unsigned int>(digits[i + 1]) << 12);
            out.push_back(static_cast<unsigned char>((n >> 16) & 0xFF));
        }
        else if (rem == 3)
        {
            const unsigned int n = (static_cast<unsigned int>(digits[i]) << 18) | (static_cast<unsigned int>(digits[i + 1]) << 12) |
                                   (static_cast<unsigned int>(digits[i + 2]) << 6);
            out.push_back(static_cast<unsigned char>((n >> 16) & 0xFF));
            out.push_back(static_cast<unsigned char>((n >> 8) & 0xFF));
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::string armorEncode(const std::string& label, const std::vector<unsigned char>& data)
{
    try
    {
        std::string out;
        out += "-----BEGIN " + label + "-----\r\n";
        out += "Version: HashCryptoLib CPgpEngine\r\n\r\n";

        const std::string b64 = base64Encode(data);
        std::size_t i = 0;
        while (i < b64.size())
        {
            const std::size_t chunk = (std::min)(static_cast<std::size_t>(64), b64.size() - i);
            out.append(b64, i, chunk);
            out += "\r\n";
            i += chunk;
        }

        const std::uint32_t crc = crc24(data);
        unsigned char crcBytes[3];
        crcBytes[0] = static_cast<unsigned char>((crc >> 16) & 0xFF);
        crcBytes[1] = static_cast<unsigned char>((crc >> 8) & 0xFF);
        crcBytes[2] = static_cast<unsigned char>(crc & 0xFF);
        out += "=" + base64Encode(std::vector<unsigned char>(crcBytes, crcBytes + 3)) + "\r\n";
        out += "-----END " + label + "-----\r\n";
        return out;
    }
    catch (...)
    {
        return std::string();
    }
}
// -----------------------------------------------------------------------------

// Parses one armored block starting at the first "-----BEGIN " found in text. blockTypeOut
// receives the label between "-----BEGIN " and "-----" (e.g. "PGP PUBLIC KEY BLOCK"); dataOut
// receives the decoded binary payload. The trailing "=<4-char-crc24>" line is verified against
// the decoded payload when present; a mismatching checksum is treated as a parse failure.
bool armorDecode(const std::string& text, std::string& blockTypeOut, std::vector<unsigned char>& dataOut)
{
    try
    {
        const std::size_t beginPos = text.find("-----BEGIN ");
        if (beginPos == std::string::npos)
        {
            return false;
        }
        const std::size_t labelStart = beginPos + 11;
        const std::size_t labelEnd = text.find("-----", labelStart);
        if (labelEnd == std::string::npos)
        {
            return false;
        }
        blockTypeOut = text.substr(labelStart, labelEnd - labelStart);

        const std::size_t headerAreaStart = labelEnd + 5;
        const std::size_t blankLf = text.find("\n\n", headerAreaStart);
        const std::size_t blankCrLf = text.find("\r\n\r\n", headerAreaStart);
        std::size_t dataStart;
        if (blankCrLf != std::string::npos && (blankLf == std::string::npos || blankCrLf <= blankLf))
        {
            dataStart = blankCrLf + 4;
        }
        else if (blankLf != std::string::npos)
        {
            dataStart = blankLf + 2;
        }
        else
        {
            return false;
        }

        const std::string endMarker = "-----END " + blockTypeOut + "-----";
        const std::size_t endPos = text.find(endMarker, dataStart);
        if (endPos == std::string::npos)
        {
            return false;
        }

        const std::string section = text.substr(dataStart, endPos - dataStart);
        std::vector<std::string> lines;
        {
            std::string current;
            for (std::size_t i = 0; i < section.size(); ++i)
            {
                const char c = section[i];
                if (c == '\n')
                {
                    lines.push_back(current);
                    current.clear();
                }
                else if (c != '\r')
                {
                    current += c;
                }
            }
            if (!current.empty())
            {
                lines.push_back(current);
            }
        }

        std::string dataB64;
        std::string crcB64;
        for (std::size_t i = 0; i < lines.size(); ++i)
        {
            if (lines[i].empty())
            {
                continue;
            }
            if (lines[i][0] == '=' && crcB64.empty())
            {
                crcB64 = lines[i].substr(1);
            }
            else
            {
                dataB64 += lines[i];
            }
        }

        if (!base64Decode(dataB64, dataOut))
        {
            return false;
        }

        if (!crcB64.empty())
        {
            std::vector<unsigned char> crcBytes;
            if (base64Decode(crcB64, crcBytes) && crcBytes.size() == 3)
            {
                const std::uint32_t storedCrc = (static_cast<std::uint32_t>(crcBytes[0]) << 16) |
                                                 (static_cast<std::uint32_t>(crcBytes[1]) << 8) | crcBytes[2];
                if (crc24(dataOut) != storedCrc)
                {
                    return false;
                }
            }
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// RFC 4880 v4 key packets (section 5.5) -- fingerprint/Key ID (section 12.2), String-to-Key
// (section 3.7.1.3, Iterated+Salted) secret-key protection (section 5.5.3, usage octet 254).
// ================================================================================================

void computeFingerprintAndKeyId(const std::vector<unsigned char>& publicKeyPacketBody, unsigned char fingerprintOut[20], unsigned char keyIdOut[8])
{
    try
    {
        std::vector<unsigned char> data;
        data.push_back(0x99);
        appendBigEndian16(data, static_cast<std::uint16_t>(publicKeyPacketBody.size()));
        appendAll(data, publicKeyPacketBody);
        CryptoPP::SHA1().CalculateDigest(fingerprintOut, data.data(), data.size());
        std::memcpy(keyIdOut, fingerprintOut + 12, 8);
    }
    catch (...)
    {
        std::memset(fingerprintOut, 0, 20);
        std::memset(keyIdOut, 0, 8);
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> buildKeyHashPrefix(const std::vector<unsigned char>& publicKeyPacketBody)
{
    std::vector<unsigned char> out;
    out.push_back(0x99);
    appendBigEndian16(out, static_cast<std::uint16_t>(publicKeyPacketBody.size()));
    appendAll(out, publicKeyPacketBody);
    return out;
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> buildRsaPublicKeyPacketBody(const std::uint32_t creationTime, const CryptoPP::Integer& n, const CryptoPP::Integer& e)
{
    std::vector<unsigned char> body;
    body.push_back(4);
    appendBigEndian32(body, creationTime);
    body.push_back(1);
    appendAll(body, encodeMpi(n));
    appendAll(body, encodeMpi(e));
    return body;
}
// -----------------------------------------------------------------------------

bool parseRsaPublicKeyPacketBody(const std::vector<unsigned char>& body, CryptoPP::Integer& n, CryptoPP::Integer& e, unsigned char keyIdOut[8])
{
    try
    {
        if (body.size() < 6 || body[0] != 4 || body[5] != 1)
        {
            return false;
        }
        std::size_t pos = 6;
        if (!readMpi(body, pos, n) || !readMpi(body, pos, e))
        {
            return false;
        }
        unsigned char fingerprint[20];
        computeFingerprintAndKeyId(body, fingerprint, keyIdOut);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> buildKeyFlagsSubpacket(const unsigned char flags)
{
    std::vector<unsigned char> sub;
    std::vector<unsigned char> body(1, flags);
    appendSubpacket(sub, 27, body);
    return sub;
}
// -----------------------------------------------------------------------------

// Iterated+Salted S2K (RFC 4880 3.7.1.3): the (salt||passphrase) octets are hashed repeatedly
// until "codedCount" octets have been fed to the hash; codedCount==0x60 below yields 65536.
// keySize must be <= SHA-256's digest size (32) -- true for this engine's only user, AES-256 keys.
std::vector<unsigned char> deriveS2kKey(const char* password, const int passwordSize, const unsigned char salt[8], const unsigned char countCoded, const std::size_t keySize)
{
    try
    {
        const std::size_t codedCount = static_cast<std::size_t>(16 + (countCoded & 15)) << ((countCoded >> 4) + 6);

        std::vector<unsigned char> saltedPassword;
        appendAll(saltedPassword, std::vector<unsigned char>(salt, salt + 8));
        saltedPassword.insert(saltedPassword.end(), reinterpret_cast<const unsigned char*>(password), reinterpret_cast<const unsigned char*>(password) + passwordSize);

        CryptoPP::SHA256 hash;
        std::size_t remaining = (codedCount < saltedPassword.size()) ? saltedPassword.size() : codedCount;
        while (remaining > 0)
        {
            const std::size_t chunk = (std::min)(remaining, saltedPassword.size());
            hash.Update(saltedPassword.data(), chunk);
            remaining -= chunk;
        }

        std::vector<unsigned char> digest(hash.DigestSize());
        hash.Final(digest.data());
        digest.resize(keySize);
        return digest;
    }
    catch (...)
    {
        return std::vector<unsigned char>();
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> buildSecretKeyPacketBody(const std::vector<unsigned char>& publicKeyPacketBody, const CryptoPP::RSA::PrivateKey& privateKey, const char* password, const int passwordSize)
{
    try
    {
        CryptoPP::AutoSeededRandomPool rng;

        std::vector<unsigned char> cleartext;
        appendAll(cleartext, encodeMpi(privateKey.GetPrivateExponent()));
        appendAll(cleartext, encodeMpi(privateKey.GetPrime1()));
        appendAll(cleartext, encodeMpi(privateKey.GetPrime2()));
        appendAll(cleartext, encodeMpi(privateKey.GetMultiplicativeInverseOfPrime2ModPrime1()));

        unsigned char sha1Check[20];
        CryptoPP::SHA1().CalculateDigest(sha1Check, cleartext.data(), cleartext.size());
        std::vector<unsigned char> plainWithCheck = cleartext;
        appendAll(plainWithCheck, std::vector<unsigned char>(sha1Check, sha1Check + 20));

        unsigned char salt[8];
        rng.GenerateBlock(salt, 8);
        const unsigned char countCoded = 0x60;
        const std::vector<unsigned char> s2kKey = deriveS2kKey(password, passwordSize, salt, countCoded, 32);
        if (s2kKey.size() != 32)
        {
            return std::vector<unsigned char>();
        }

        unsigned char iv[16];
        rng.GenerateBlock(iv, 16);

        std::vector<unsigned char> encrypted(plainWithCheck.size());
        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(s2kKey.data(), s2kKey.size(), iv, 16);
        enc.ProcessData(encrypted.data(), plainWithCheck.data(), plainWithCheck.size());

        std::vector<unsigned char> body;
        appendAll(body, publicKeyPacketBody);
        body.push_back(254);
        body.push_back(9);
        body.push_back(3);
        body.push_back(8);
        appendAll(body, std::vector<unsigned char>(salt, salt + 8));
        body.push_back(countCoded);
        appendAll(body, std::vector<unsigned char>(iv, iv + 16));
        appendAll(body, encrypted);
        return body;
    }
    catch (...)
    {
        return std::vector<unsigned char>();
    }
}
// -----------------------------------------------------------------------------

bool checkPasswordHash(const unsigned char storedHash[32], const char* password, const int passwordSize)
{
    try
    {
        unsigned char computed[32];
        CryptoPP::SHA256().CalculateDigest(computed, reinterpret_cast<const CryptoPP::byte*>(password), static_cast<std::size_t>(passwordSize));
        return std::memcmp(computed, storedHash, 32) == 0;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// RFC 4880 v4 signature packets (section 5.2) -- construction (self-cert/subkey-binding/detached/
// clear-sign all share this) and verification.
// ================================================================================================

std::vector<unsigned char> buildSignaturePacket(const CryptoPP::RSA::PrivateKey& signingKey, const unsigned char signatureType, const std::vector<unsigned char>& documentData, const std::vector<unsigned char>& extraHashedSubpacket, const unsigned char issuerKeyId[8])
{
    try
    {
        CryptoPP::AutoSeededRandomPool rng;
        const std::uint32_t now = static_cast<std::uint32_t>(std::time(nullptr));

        std::vector<unsigned char> hashedSubpackets;
        {
            std::vector<unsigned char> timeBody;
            appendBigEndian32(timeBody, now);
            appendSubpacket(hashedSubpackets, 2, timeBody);
        }
        appendAll(hashedSubpackets, extraHashedSubpacket);

        std::vector<unsigned char> unhashedSubpackets;
        {
            std::vector<unsigned char> issuerBody(issuerKeyId, issuerKeyId + 8);
            appendSubpacket(unhashedSubpackets, 16, issuerBody);
        }

        std::vector<unsigned char> toBeHashed;
        appendAll(toBeHashed, documentData);
        toBeHashed.push_back(4);
        toBeHashed.push_back(signatureType);
        toBeHashed.push_back(1);
        toBeHashed.push_back(8);
        appendBigEndian16(toBeHashed, static_cast<std::uint16_t>(hashedSubpackets.size()));
        appendAll(toBeHashed, hashedSubpackets);

        const std::size_t hashedPortionLength = 6 + hashedSubpackets.size();
        toBeHashed.push_back(4);
        toBeHashed.push_back(0xFF);
        appendBigEndian32(toBeHashed, static_cast<std::uint32_t>(hashedPortionLength));

        unsigned char leftHash[32];
        CryptoPP::SHA256().CalculateDigest(leftHash, toBeHashed.data(), toBeHashed.size());

        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(signingKey);
        std::vector<unsigned char> rawSignature(signer.SignatureLength());
        signer.SignMessage(rng, toBeHashed.data(), toBeHashed.size(), rawSignature.data());
        const CryptoPP::Integer sigInt(rawSignature.data(), rawSignature.size());
        const std::vector<unsigned char> sigMpi = encodeMpi(sigInt);

        std::vector<unsigned char> body;
        body.push_back(4);
        body.push_back(signatureType);
        body.push_back(1);
        body.push_back(8);
        appendBigEndian16(body, static_cast<std::uint16_t>(hashedSubpackets.size()));
        appendAll(body, hashedSubpackets);
        appendBigEndian16(body, static_cast<std::uint16_t>(unhashedSubpackets.size()));
        appendAll(body, unhashedSubpackets);
        body.push_back(leftHash[0]);
        body.push_back(leftHash[1]);
        appendAll(body, sigMpi);

        return writePacket(PGP_TAG_SIGNATURE, body);
    }
    catch (...)
    {
        return std::vector<unsigned char>();
    }
}
// -----------------------------------------------------------------------------

struct ParsedSignature
{
    bool valid;
    unsigned char signatureType;
    unsigned char hashAlgorithm;
    std::vector<unsigned char> hashedSubpackets;
    std::vector<unsigned char> signatureMpiValue;

    ParsedSignature() : valid(false), signatureType(0), hashAlgorithm(0) {}
};
// -----------------------------------------------------------------------------

ParsedSignature parseSignaturePacketBody(const std::vector<unsigned char>& body)
{
    ParsedSignature result;
    try
    {
        if (body.size() < 6 || body[0] != 4)
        {
            return result;
        }
        std::size_t pos = 1;
        result.signatureType = body[pos]; pos += 1;
        const unsigned char pkAlgo = body[pos]; pos += 1;
        if (pkAlgo != 1)
        {
            return result;
        }
        result.hashAlgorithm = body[pos]; pos += 1;
        if (result.hashAlgorithm != 8)
        {
            return result;
        }

        if (pos + 2 > body.size())
        {
            return result;
        }
        const std::size_t hashedLength = readBigEndian16(body, pos);
        pos += 2;
        if (pos + hashedLength > body.size())
        {
            return result;
        }
        result.hashedSubpackets.assign(body.begin() + pos, body.begin() + pos + hashedLength);
        pos += hashedLength;

        if (pos + 2 > body.size())
        {
            return result;
        }
        const std::size_t unhashedLength = readBigEndian16(body, pos);
        pos += 2;
        if (pos + unhashedLength > body.size())
        {
            return result;
        }
        pos += unhashedLength;

        if (pos + 2 > body.size())
        {
            return result;
        }
        pos += 2;

        if (pos + 2 > body.size())
        {
            return result;
        }
        const std::size_t sigBitLength = readBigEndian16(body, pos);
        pos += 2;
        const std::size_t sigByteLength = (sigBitLength + 7) / 8;
        if (pos + sigByteLength > body.size())
        {
            return result;
        }
        result.signatureMpiValue.assign(body.begin() + pos, body.begin() + pos + sigByteLength);

        result.valid = true;
        return result;
    }
    catch (...)
    {
        result.valid = false;
        return result;
    }
}
// -----------------------------------------------------------------------------

// signaturePacketBytes is a full packet (header+body). Returns false only on a parse/technical
// failure (isValid left untouched); a cryptographically invalid signature is reported as
// *isValid=false with a true return (same NO_ERROR/*isValid split CCryptoApi::VerifyBuffer uses).
bool verifySignaturePacket(const CryptoPP::RSA::PublicKey& verifyingKey, const std::vector<unsigned char>& documentData, const std::vector<unsigned char>& signaturePacketBytes, bool* isValid)
{
    try
    {
        std::size_t pos = 0;
        unsigned char tag = 0;
        std::size_t bodyLength = 0;
        if (!readPacketHeader(signaturePacketBytes, pos, tag, bodyLength) || tag != PGP_TAG_SIGNATURE)
        {
            return false;
        }
        if (pos + bodyLength > signaturePacketBytes.size())
        {
            return false;
        }

        const std::vector<unsigned char> body(signaturePacketBytes.begin() + pos, signaturePacketBytes.begin() + pos + bodyLength);
        const ParsedSignature parsed = parseSignaturePacketBody(body);
        if (!parsed.valid)
        {
            return false;
        }

        std::vector<unsigned char> toBeHashed;
        appendAll(toBeHashed, documentData);
        toBeHashed.push_back(4);
        toBeHashed.push_back(parsed.signatureType);
        toBeHashed.push_back(1);
        toBeHashed.push_back(8);
        appendBigEndian16(toBeHashed, static_cast<std::uint16_t>(parsed.hashedSubpackets.size()));
        appendAll(toBeHashed, parsed.hashedSubpackets);

        const std::size_t hashedPortionLength = 6 + parsed.hashedSubpackets.size();
        toBeHashed.push_back(4);
        toBeHashed.push_back(0xFF);
        appendBigEndian32(toBeHashed, static_cast<std::uint32_t>(hashedPortionLength));

        const std::size_t fixedLength = rsaModulusByteLength(verifyingKey.GetModulus());
        std::vector<unsigned char> fixedSignature(fixedLength, 0);
        const CryptoPP::Integer sigInt(parsed.signatureMpiValue.data(), parsed.signatureMpiValue.size());
        sigInt.Encode(fixedSignature.data(), fixedLength);

        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(verifyingKey);
        *isValid = verifier.VerifyMessage(toBeHashed.data(), toBeHashed.size(), fixedSignature.data(), fixedSignature.size());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// RFC 4880 section 7 clear-sign canonicalization: trailing whitespace (space/tab) and any line-
// ending CR are stripped before hashing/dash-escaping; every line (including the last) is hashed
// and displayed with a trailing CRLF -- a deliberate v1 simplification of the original-trailing-
// newline edge case, self-consistent since this engine also verifies what it produces.
// ================================================================================================

std::vector<std::string> splitAndCanonicalizeLines(const std::string& text)
{
    std::vector<std::string> lines;
    std::string current;
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        const char c = text[i];
        if (c == '\n')
        {
            if (!current.empty() && current[current.size() - 1] == '\r')
            {
                current.erase(current.size() - 1);
            }
            while (!current.empty() && (current[current.size() - 1] == ' ' || current[current.size() - 1] == '\t'))
            {
                current.erase(current.size() - 1);
            }
            lines.push_back(current);
            current.clear();
        }
        else
        {
            current += c;
        }
    }
    if (!current.empty() || !lines.empty())
    {
        if (!current.empty() && current[current.size() - 1] == '\r')
        {
            current.erase(current.size() - 1);
        }
        while (!current.empty() && (current[current.size() - 1] == ' ' || current[current.size() - 1] == '\t'))
        {
            current.erase(current.size() - 1);
        }
        lines.push_back(current);
    }
    return lines;
}
// -----------------------------------------------------------------------------

// ================================================================================================
// RFC 4880 message body packets (sections 5.6/5.9/5.13/5.14) -- Compressed Data (ZIP), Literal
// Data, Sym. Encrypted Integrity Protected Data (AES-256-CFB, zero IV, SHA-1 MDC).
// ================================================================================================

bool buildEncryptedMessage(const CryptoPP::RSA::PublicKey& recipientKey, const unsigned char recipientKeyId[8], const unsigned char* plaintext, const std::size_t plaintextSize, std::vector<unsigned char>& out)
{
    try
    {
        CryptoPP::AutoSeededRandomPool rng;

        std::vector<unsigned char> literalBody;
        literalBody.push_back('b');
        literalBody.push_back(0);
        appendBigEndian32(literalBody, 0);
        if (plaintextSize > 0)
        {
            literalBody.insert(literalBody.end(), plaintext, plaintext + plaintextSize);
        }
        const std::vector<unsigned char> literalPacket = writePacket(PGP_TAG_LITERAL_DATA, literalBody);

        std::string deflated;
        {
            CryptoPP::Deflator deflator(new CryptoPP::StringSink(deflated));
            deflator.Put(literalPacket.data(), literalPacket.size());
            deflator.MessageEnd();
        }
        std::vector<unsigned char> compressedBody;
        compressedBody.push_back(1);
        compressedBody.insert(compressedBody.end(), deflated.begin(), deflated.end());
        const std::vector<unsigned char> compressedPacket = writePacket(PGP_TAG_COMPRESSED_DATA, compressedBody);

        unsigned char sessionKey[32];
        rng.GenerateBlock(sessionKey, 32);

        unsigned char prefix[18];
        rng.GenerateBlock(prefix, 16);
        prefix[16] = prefix[14];
        prefix[17] = prefix[15];

        std::vector<unsigned char> plainForCfb;
        plainForCfb.insert(plainForCfb.end(), prefix, prefix + 18);
        appendAll(plainForCfb, compressedPacket);

        unsigned char mdcHash[20];
        {
            std::vector<unsigned char> mdcPreimage = plainForCfb;
            mdcPreimage.push_back(0xD3);
            mdcPreimage.push_back(0x14);
            CryptoPP::SHA1().CalculateDigest(mdcHash, mdcPreimage.data(), mdcPreimage.size());
        }
        plainForCfb.push_back(0xD3);
        plainForCfb.push_back(0x14);
        plainForCfb.insert(plainForCfb.end(), mdcHash, mdcHash + 20);

        std::vector<unsigned char> cfbCiphertext(plainForCfb.size());
        {
            unsigned char zeroIv[16];
            std::memset(zeroIv, 0, 16);
            CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
            enc.SetKeyWithIV(sessionKey, 32, zeroIv, 16);
            enc.ProcessData(cfbCiphertext.data(), plainForCfb.data(), plainForCfb.size());
        }

        std::vector<unsigned char> seipBody;
        seipBody.push_back(1);
        appendAll(seipBody, cfbCiphertext);
        const std::vector<unsigned char> seipPacket = writePacket(PGP_TAG_SEIP, seipBody);

        unsigned char sessionKeyPlain[35];
        sessionKeyPlain[0] = 9;
        std::memcpy(sessionKeyPlain + 1, sessionKey, 32);
        {
            unsigned int checksum = 0;
            for (int i = 0; i < 32; ++i)
            {
                checksum += sessionKey[i];
            }
            sessionKeyPlain[33] = static_cast<unsigned char>((checksum >> 8) & 0xFF);
            sessionKeyPlain[34] = static_cast<unsigned char>(checksum & 0xFF);
        }

        CryptoPP::RSAES<CryptoPP::PKCS1v15>::Encryptor encryptor(recipientKey);
        std::vector<unsigned char> pkcsCipher(encryptor.FixedCiphertextLength());
        encryptor.Encrypt(rng, sessionKeyPlain, 35, pkcsCipher.data());
        const CryptoPP::Integer cipherInt(pkcsCipher.data(), pkcsCipher.size());
        const std::vector<unsigned char> cipherMpi = encodeMpi(cipherInt);

        std::vector<unsigned char> pkeskBody;
        pkeskBody.push_back(3);
        pkeskBody.insert(pkeskBody.end(), recipientKeyId, recipientKeyId + 8);
        pkeskBody.push_back(1);
        appendAll(pkeskBody, cipherMpi);
        const std::vector<unsigned char> pkeskPacket = writePacket(PGP_TAG_PKESK, pkeskBody);

        out.clear();
        appendAll(out, pkeskPacket);
        appendAll(out, seipPacket);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool parseAndDecryptMessage(const CryptoPP::RSA::PrivateKey& recipientPrivateKey, const std::vector<unsigned char>& message, std::vector<unsigned char>& outPlaintext)
{
    try
    {
        std::size_t pos = 0;
        unsigned char tag = 0;
        std::size_t bodyLength = 0;
        if (!readPacketHeader(message, pos, tag, bodyLength) || tag != PGP_TAG_PKESK)
        {
            return false;
        }
        const std::size_t pkeskEnd = pos + bodyLength;
        if (pkeskEnd > message.size())
        {
            return false;
        }

        std::size_t p = pos;
        if (message[p] != 3)
        {
            return false;
        }
        p += 1;
        p += 8;
        if (message[p] != 1)
        {
            return false;
        }
        p += 1;
        if (p + 2 > pkeskEnd)
        {
            return false;
        }
        const std::size_t bitLength = readBigEndian16(message, p);
        p += 2;
        const std::size_t byteLength = (bitLength + 7) / 8;
        if (p + byteLength > pkeskEnd)
        {
            return false;
        }
        const CryptoPP::Integer cipherInt(&message[p], byteLength);
        pos = pkeskEnd;

        const std::size_t modulusLength = rsaModulusByteLength(recipientPrivateKey.GetModulus());
        std::vector<unsigned char> fixedCipher(modulusLength, 0);
        cipherInt.Encode(fixedCipher.data(), modulusLength);

        CryptoPP::RSAES<CryptoPP::PKCS1v15>::Decryptor decryptor(recipientPrivateKey);
        std::vector<unsigned char> sessionPlain(decryptor.FixedMaxPlaintextLength());
        CryptoPP::AutoSeededRandomPool rng;
        const CryptoPP::DecodingResult result = decryptor.Decrypt(rng, fixedCipher.data(), fixedCipher.size(), sessionPlain.data());
        if (!result.isValidCoding)
        {
            return false;
        }
        sessionPlain.resize(result.messageLength);
        if (sessionPlain.empty())
        {
            return false;
        }
        // v1 always PRODUCES AES-256 (see buildEncryptedMessage), but real-world senders (verified
        // against GnuPG 2.5.21, which defaults to AES-128 for a recipient key with no advertised
        // preference) may choose any AES family member -- accept all three to decrypt their
        // messages, not just our own.
        std::size_t sessionKeyLength = 0;
        switch (sessionPlain[0])
        {
            case 7: sessionKeyLength = 16; break;
            case 8: sessionKeyLength = 24; break;
            case 9: sessionKeyLength = 32; break;
            default: return false;
        }
        if (sessionPlain.size() != 1 + sessionKeyLength + 2)
        {
            return false;
        }
        std::vector<unsigned char> sessionKey(sessionKeyLength);
        std::memcpy(sessionKey.data(), &sessionPlain[1], sessionKeyLength);
        unsigned int checksum = 0;
        for (std::size_t i = 0; i < sessionKeyLength; ++i)
        {
            checksum += sessionKey[i];
        }
        const unsigned int storedChecksum = (static_cast<unsigned int>(sessionPlain[1 + sessionKeyLength]) << 8) | sessionPlain[1 + sessionKeyLength + 1];
        if ((checksum & 0xFFFF) != storedChecksum)
        {
            return false;
        }

        unsigned char seipTag = 0;
        std::size_t seipBodyLength = 0;
        if (!readPacketHeader(message, pos, seipTag, seipBodyLength) || seipTag != PGP_TAG_SEIP)
        {
            return false;
        }
        if (pos + seipBodyLength > message.size() || seipBodyLength < 1 || message[pos] != 1)
        {
            return false;
        }
        const unsigned char* encStart = &message[pos + 1];
        const std::size_t encLength = seipBodyLength - 1;

        std::vector<unsigned char> plainForCfb(encLength);
        {
            unsigned char zeroIv[16];
            std::memset(zeroIv, 0, 16);
            CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(sessionKey.data(), sessionKey.size(), zeroIv, 16);
            dec.ProcessData(plainForCfb.data(), encStart, encLength);
        }

        if (plainForCfb.size() < 18 + 2 + 20)
        {
            return false;
        }
        const std::size_t mdcHashOffset = plainForCfb.size() - 20;
        const std::size_t mdcTagOffset = mdcHashOffset - 2;
        if (plainForCfb[mdcTagOffset] != 0xD3 || plainForCfb[mdcTagOffset + 1] != 0x14)
        {
            return false;
        }
        unsigned char computedMdc[20];
        CryptoPP::SHA1().CalculateDigest(computedMdc, plainForCfb.data(), mdcHashOffset);
        if (std::memcmp(computedMdc, &plainForCfb[mdcHashOffset], 20) != 0)
        {
            return false;
        }

        std::size_t innerPos = 18;
        const std::size_t innerEnd = mdcTagOffset;
        unsigned char innerTag = 0;
        std::size_t innerLength = 0;
        if (!readPacketHeader(plainForCfb, innerPos, innerTag, innerLength, innerEnd) || innerPos + innerLength > innerEnd)
        {
            return false;
        }

        const unsigned char* literalBody = nullptr;
        std::size_t literalBodyLength = 0;
        std::vector<unsigned char> decompressedPacket;

        if (innerTag == PGP_TAG_COMPRESSED_DATA)
        {
            if (innerLength < 1)
            {
                return false;
            }
            const unsigned char compAlgo = plainForCfb[innerPos];
            const unsigned char* compData = &plainForCfb[innerPos + 1];
            const std::size_t compDataLength = innerLength - 1;

            std::string decompressed;
            if (compAlgo == 0)
            {
                decompressed.assign(reinterpret_cast<const char*>(compData), compDataLength);
            }
            else if (compAlgo == 1)
            {
                CryptoPP::Inflator inflator(new CryptoPP::StringSink(decompressed));
                inflator.Put(compData, compDataLength);
                inflator.MessageEnd();
            }
            else if (compAlgo == 2)
            {
                CryptoPP::ZlibDecompressor inflator(new CryptoPP::StringSink(decompressed));
                inflator.Put(compData, compDataLength);
                inflator.MessageEnd();
            }
            else
            {
                return false;
            }
            decompressedPacket.assign(decompressed.begin(), decompressed.end());

            std::size_t lp = 0;
            unsigned char lt = 0;
            std::size_t ll = 0;
            if (!readPacketHeader(decompressedPacket, lp, lt, ll) || lt != PGP_TAG_LITERAL_DATA || lp + ll > decompressedPacket.size())
            {
                return false;
            }
            literalBody = &decompressedPacket[lp];
            literalBodyLength = ll;
        }
        else if (innerTag == PGP_TAG_LITERAL_DATA)
        {
            literalBody = &plainForCfb[innerPos];
            literalBodyLength = innerLength;
        }
        else
        {
            return false;
        }

        if (literalBodyLength < 6)
        {
            return false;
        }
        const unsigned char filenameLength = literalBody[1];
        const std::size_t contentOffset = 1 + 1 + filenameLength + 4;
        if (contentOffset > literalBodyLength)
        {
            return false;
        }
        outPlaintext.assign(literalBody + contentOffset, literalBody + literalBodyLength);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// ================================================================================================
// Streaming (chunked, O(chunk size) memory) file-based variants of the buffer-based helpers
// above -- see PgpEngine.h's own comment on EncryptFile/DecryptFile/SignFile/VerifyFile for the
// design tradeoffs (no compression on the encrypt side so every packet length is exactly known
// upfront; DecryptFile writes to a temp file and only keeps it if the trailing MDC check passes).
// ================================================================================================

int encryptFileStreaming(const CryptoPP::RSA::PublicKey& recipientKey, const unsigned char recipientKeyId[8], HANDLE inputFileHandle, const unsigned long long fileSize, HANDLE outputFileHandle, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        CryptoPP::AutoSeededRandomPool rng;

        unsigned char sessionKey[32];
        rng.GenerateBlock(sessionKey, 32);
        unsigned char sessionKeyPlain[35];
        sessionKeyPlain[0] = 9;
        std::memcpy(sessionKeyPlain + 1, sessionKey, 32);
        {
            unsigned int checksum = 0;
            for (int i = 0; i < 32; ++i)
            {
                checksum += sessionKey[i];
            }
            sessionKeyPlain[33] = static_cast<unsigned char>((checksum >> 8) & 0xFF);
            sessionKeyPlain[34] = static_cast<unsigned char>(checksum & 0xFF);
        }

        CryptoPP::RSAES<CryptoPP::PKCS1v15>::Encryptor encryptor(recipientKey);
        std::vector<unsigned char> pkcsCipher(encryptor.FixedCiphertextLength());
        encryptor.Encrypt(rng, sessionKeyPlain, 35, pkcsCipher.data());
        const CryptoPP::Integer cipherInt(pkcsCipher.data(), pkcsCipher.size());
        const std::vector<unsigned char> cipherMpi = encodeMpi(cipherInt);

        std::vector<unsigned char> pkeskBody;
        pkeskBody.push_back(3);
        pkeskBody.insert(pkeskBody.end(), recipientKeyId, recipientKeyId + 8);
        pkeskBody.push_back(1);
        appendAll(pkeskBody, cipherMpi);
        const std::vector<unsigned char> pkeskPacket = writePacket(PGP_TAG_PKESK, pkeskBody);
        if (!writeFileExact(outputFileHandle, pkeskPacket.data(), static_cast<DWORD>(pkeskPacket.size())))
        {
            return FILE_IO_ERROR;
        }

        // Literal Data (tag 11) header: no compression on this path, so this length is exactly
        // computable from fileSize before any content byte is written or read.
        const std::size_t literalBodyLength = 6 + static_cast<std::size_t>(fileSize);
        std::vector<unsigned char> literalHeader;
        literalHeader.push_back(static_cast<unsigned char>(0xC0 | PGP_TAG_LITERAL_DATA));
        appendNewFormatLength(literalHeader, literalBodyLength);

        std::vector<unsigned char> literalPrefix;
        literalPrefix.push_back('b');
        literalPrefix.push_back(0);
        appendBigEndian32(literalPrefix, 0);

        const std::size_t innerContentLength = literalHeader.size() + literalBodyLength;
        const std::size_t plainForCfbLength = 18 + innerContentLength + 2 + 20;
        const std::size_t seipBodyLength = 1 + plainForCfbLength;

        std::vector<unsigned char> seipHeader;
        seipHeader.push_back(static_cast<unsigned char>(0xC0 | PGP_TAG_SEIP));
        appendNewFormatLength(seipHeader, seipBodyLength);
        if (!writeFileExact(outputFileHandle, seipHeader.data(), static_cast<DWORD>(seipHeader.size())))
        {
            return FILE_IO_ERROR;
        }
        const unsigned char seipVersion = 1;
        if (!writeFileExact(outputFileHandle, &seipVersion, 1))
        {
            return FILE_IO_ERROR;
        }

        unsigned char zeroIv[16];
        std::memset(zeroIv, 0, 16);
        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfb;
        cfb.SetKeyWithIV(sessionKey, 32, zeroIv, 16);
        CryptoPP::SHA1 mdc;

        unsigned char prefix[18];
        rng.GenerateBlock(prefix, 16);
        prefix[16] = prefix[14];
        prefix[17] = prefix[15];

        unsigned char prefixCipher[18];
        mdc.Update(prefix, 18);
        cfb.ProcessData(prefixCipher, prefix, 18);
        if (!writeFileExact(outputFileHandle, prefixCipher, 18))
        {
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> literalHeaderCipher(literalHeader.size());
        mdc.Update(literalHeader.data(), literalHeader.size());
        cfb.ProcessData(literalHeaderCipher.data(), literalHeader.data(), literalHeader.size());
        if (!writeFileExact(outputFileHandle, literalHeaderCipher.data(), static_cast<DWORD>(literalHeaderCipher.size())))
        {
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> literalPrefixCipher(literalPrefix.size());
        mdc.Update(literalPrefix.data(), literalPrefix.size());
        cfb.ProcessData(literalPrefixCipher.data(), literalPrefix.data(), literalPrefix.size());
        if (!writeFileExact(outputFileHandle, literalPrefixCipher.data(), static_cast<DWORD>(literalPrefixCipher.size())))
        {
            return FILE_IO_ERROR;
        }

        std::vector<unsigned char> plainChunk(PGP_FILE_CHUNK_SIZE);
        std::vector<unsigned char> cipherChunk(PGP_FILE_CHUNK_SIZE);
        unsigned long long processedBytes = 0;
        for (;;)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(inputFileHandle, plainChunk.data(), static_cast<DWORD>(plainChunk.size()), &bytesRead, nullptr))
            {
                return FILE_IO_ERROR;
            }
            if (bytesRead == 0)
            {
                break;
            }

            mdc.Update(plainChunk.data(), bytesRead);
            cfb.ProcessData(cipherChunk.data(), plainChunk.data(), bytesRead);
            if (!writeFileExact(outputFileHandle, cipherChunk.data(), bytesRead))
            {
                return FILE_IO_ERROR;
            }

            processedBytes += bytesRead;
            if (onProgress)
            {
                const double percentage = fileSize > 0 ? (static_cast<double>(processedBytes) / static_cast<double>(fileSize)) * 100.0 : 0.0;
                if (!onProgress(processedBytes, fileSize, percentage, progressUserData))
                {
                    return OPERATION_CANCELLED;
                }
            }
        }

        unsigned char trailerPlain[22];
        trailerPlain[0] = 0xD3;
        trailerPlain[1] = 0x14;
        mdc.Update(trailerPlain, 2);
        unsigned char mdcDigest[20];
        mdc.Final(mdcDigest);
        std::memcpy(trailerPlain + 2, mdcDigest, 20);

        unsigned char trailerCipher[22];
        cfb.ProcessData(trailerCipher, trailerPlain, 22);
        if (!writeFileExact(outputFileHandle, trailerCipher, 22))
        {
            return FILE_IO_ERROR;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int signFileStreaming(const CryptoPP::RSA::PrivateKey& signingKey, HANDLE inputFileHandle, const unsigned long long fileSize, const unsigned char issuerKeyId[8], ProgressCallback onProgress, void* progressUserData, std::vector<unsigned char>& outSignaturePacket)
{
    try
    {
        const std::uint32_t now = static_cast<std::uint32_t>(std::time(nullptr));
        const unsigned char signatureType = 0x00;

        std::vector<unsigned char> hashedSubpackets;
        {
            std::vector<unsigned char> timeBody;
            appendBigEndian32(timeBody, now);
            appendSubpacket(hashedSubpackets, 2, timeBody);
        }
        std::vector<unsigned char> unhashedSubpackets;
        {
            std::vector<unsigned char> issuerBody(issuerKeyId, issuerKeyId + 8);
            appendSubpacket(unhashedSubpackets, 16, issuerBody);
        }

        // version,sigType,pkAlgo,hashAlgo,hashedSubpacketsLen,hashedSubpackets,trailer(6) -- the
        // part of "toBeHashed" that comes AFTER the (streamed, never fully buffered) document
        // data; see buildSignaturePacket's own comment for the buffer-based equivalent.
        std::vector<unsigned char> trailerSuffix;
        trailerSuffix.push_back(4);
        trailerSuffix.push_back(signatureType);
        trailerSuffix.push_back(1);
        trailerSuffix.push_back(8);
        appendBigEndian16(trailerSuffix, static_cast<std::uint16_t>(hashedSubpackets.size()));
        appendAll(trailerSuffix, hashedSubpackets);
        const std::size_t hashedPortionLength = 6 + hashedSubpackets.size();
        trailerSuffix.push_back(4);
        trailerSuffix.push_back(0xFF);
        appendBigEndian32(trailerSuffix, static_cast<std::uint32_t>(hashedPortionLength));

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(signingKey);
        std::unique_ptr<CryptoPP::PK_MessageAccumulator> accumulator(signer.NewSignatureAccumulator(rng));
        // A second, independent SHA-256 run purely to recover the signature packet's own "left
        // 16 bits of hash" quick-check field -- the RSA signer's accumulator above does not
        // expose its internal digest, only the final signature, so this is computed in parallel
        // over the exact same streamed bytes rather than re-reading the file a second time.
        CryptoPP::SHA256 leftHashDigest;

        std::vector<unsigned char> chunk(PGP_FILE_CHUNK_SIZE);
        unsigned long long processedBytes = 0;
        for (;;)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(inputFileHandle, chunk.data(), static_cast<DWORD>(chunk.size()), &bytesRead, nullptr))
            {
                return FILE_IO_ERROR;
            }
            if (bytesRead == 0)
            {
                break;
            }

            accumulator->Update(chunk.data(), bytesRead);
            leftHashDigest.Update(chunk.data(), bytesRead);

            processedBytes += bytesRead;
            if (onProgress)
            {
                const double percentage = fileSize > 0 ? (static_cast<double>(processedBytes) / static_cast<double>(fileSize)) * 100.0 : 0.0;
                if (!onProgress(processedBytes, fileSize, percentage, progressUserData))
                {
                    return OPERATION_CANCELLED;
                }
            }
        }
        accumulator->Update(trailerSuffix.data(), trailerSuffix.size());
        leftHashDigest.Update(trailerSuffix.data(), trailerSuffix.size());

        unsigned char leftHash[32];
        leftHashDigest.Final(leftHash);

        std::vector<unsigned char> rawSignature(signer.SignatureLength());
        signer.Sign(rng, accumulator.release(), rawSignature.data());
        const CryptoPP::Integer sigInt(rawSignature.data(), rawSignature.size());
        const std::vector<unsigned char> sigMpi = encodeMpi(sigInt);

        std::vector<unsigned char> body;
        body.push_back(4);
        body.push_back(signatureType);
        body.push_back(1);
        body.push_back(8);
        appendBigEndian16(body, static_cast<std::uint16_t>(hashedSubpackets.size()));
        appendAll(body, hashedSubpackets);
        appendBigEndian16(body, static_cast<std::uint16_t>(unhashedSubpackets.size()));
        appendAll(body, unhashedSubpackets);
        body.push_back(leftHash[0]);
        body.push_back(leftHash[1]);
        appendAll(body, sigMpi);

        outSignaturePacket = writePacket(PGP_TAG_SIGNATURE, body);
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int verifyFileStreaming(const CryptoPP::RSA::PublicKey& verifyingKey, HANDLE inputFileHandle, const unsigned long long fileSize, const std::vector<unsigned char>& signaturePacketBytes, bool* isValid, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        std::size_t pos = 0;
        unsigned char tag = 0;
        std::size_t bodyLength = 0;
        if (!readPacketHeader(signaturePacketBytes, pos, tag, bodyLength) || tag != PGP_TAG_SIGNATURE || pos + bodyLength > signaturePacketBytes.size())
        {
            return INVALID_DATA;
        }
        const std::vector<unsigned char> body(signaturePacketBytes.begin() + pos, signaturePacketBytes.begin() + pos + bodyLength);
        const ParsedSignature parsed = parseSignaturePacketBody(body);
        if (!parsed.valid)
        {
            return INVALID_DATA;
        }

        std::vector<unsigned char> trailerSuffix;
        trailerSuffix.push_back(4);
        trailerSuffix.push_back(parsed.signatureType);
        trailerSuffix.push_back(1);
        trailerSuffix.push_back(8);
        appendBigEndian16(trailerSuffix, static_cast<std::uint16_t>(parsed.hashedSubpackets.size()));
        appendAll(trailerSuffix, parsed.hashedSubpackets);
        const std::size_t hashedPortionLength = 6 + parsed.hashedSubpackets.size();
        trailerSuffix.push_back(4);
        trailerSuffix.push_back(0xFF);
        appendBigEndian32(trailerSuffix, static_cast<std::uint32_t>(hashedPortionLength));

        const std::size_t fixedLength = rsaModulusByteLength(verifyingKey.GetModulus());
        std::vector<unsigned char> fixedSignature(fixedLength, 0);
        const CryptoPP::Integer sigInt(parsed.signatureMpiValue.data(), parsed.signatureMpiValue.size());
        sigInt.Encode(fixedSignature.data(), fixedLength);

        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(verifyingKey);
        std::unique_ptr<CryptoPP::PK_MessageAccumulator> accumulator(verifier.NewVerificationAccumulator());
        verifier.InputSignature(*accumulator, fixedSignature.data(), fixedSignature.size());

        std::vector<unsigned char> chunk(PGP_FILE_CHUNK_SIZE);
        unsigned long long processedBytes = 0;
        for (;;)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(inputFileHandle, chunk.data(), static_cast<DWORD>(chunk.size()), &bytesRead, nullptr))
            {
                return FILE_IO_ERROR;
            }
            if (bytesRead == 0)
            {
                break;
            }

            accumulator->Update(chunk.data(), bytesRead);

            processedBytes += bytesRead;
            if (onProgress)
            {
                const double percentage = fileSize > 0 ? (static_cast<double>(processedBytes) / static_cast<double>(fileSize)) * 100.0 : 0.0;
                if (!onProgress(processedBytes, fileSize, percentage, progressUserData))
                {
                    return OPERATION_CANCELLED;
                }
            }
        }
        accumulator->Update(trailerSuffix.data(), trailerSuffix.size());

        *isValid = verifier.Verify(accumulator.release());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

struct DecryptFileHeader
{
    bool ok;
    std::vector<unsigned char> sessionKey;
    std::size_t encLength;
    std::vector<unsigned char> leftoverCipher;

    DecryptFileHeader() : ok(false), encLength(0) {}
};
// -----------------------------------------------------------------------------

// Reads just enough of the file (a small, bounded prefix -- PKESK plus the SEIP header are at
// most ~550 bytes even for RSA-4096) to recover the session key and the SEIP body's exact
// length. Any ciphertext bytes read past the SEIP header in that same prefix are returned in
// leftoverCipher so decryptSeipBodyStreaming can consume them before reading more from the file.
DecryptFileHeader parseEncryptedFileHeader(HANDLE inputFileHandle, const CryptoPP::RSA::PrivateKey& recipientPrivateKey)
{
    DecryptFileHeader result;
    try
    {
        std::vector<unsigned char> buf(8192);
        DWORD bytesRead = 0;
        if (!ReadFile(inputFileHandle, buf.data(), static_cast<DWORD>(buf.size()), &bytesRead, nullptr))
        {
            return result;
        }
        buf.resize(bytesRead);

        std::size_t pos = 0;
        unsigned char tag = 0;
        std::size_t bodyLength = 0;
        if (!readPacketHeader(buf, pos, tag, bodyLength) || tag != PGP_TAG_PKESK || pos + bodyLength > buf.size())
        {
            return result;
        }
        const std::size_t pkeskEnd = pos + bodyLength;

        std::size_t p = pos;
        if (buf[p] != 3)
        {
            return result;
        }
        p += 1;
        p += 8;
        if (buf[p] != 1)
        {
            return result;
        }
        p += 1;
        if (p + 2 > pkeskEnd)
        {
            return result;
        }
        const std::size_t bitLength = readBigEndian16(buf, p);
        p += 2;
        const std::size_t byteLength = (bitLength + 7) / 8;
        if (p + byteLength > pkeskEnd)
        {
            return result;
        }
        const CryptoPP::Integer cipherInt(&buf[p], byteLength);
        pos = pkeskEnd;

        const std::size_t modulusLength = rsaModulusByteLength(recipientPrivateKey.GetModulus());
        std::vector<unsigned char> fixedCipher(modulusLength, 0);
        cipherInt.Encode(fixedCipher.data(), modulusLength);

        CryptoPP::RSAES<CryptoPP::PKCS1v15>::Decryptor decryptor(recipientPrivateKey);
        std::vector<unsigned char> sessionPlain(decryptor.FixedMaxPlaintextLength());
        CryptoPP::AutoSeededRandomPool rng;
        const CryptoPP::DecodingResult decResult = decryptor.Decrypt(rng, fixedCipher.data(), fixedCipher.size(), sessionPlain.data());
        if (!decResult.isValidCoding)
        {
            return result;
        }
        sessionPlain.resize(decResult.messageLength);
        if (sessionPlain.empty())
        {
            return result;
        }

        std::size_t sessionKeyLength = 0;
        switch (sessionPlain[0])
        {
            case 7: sessionKeyLength = 16; break;
            case 8: sessionKeyLength = 24; break;
            case 9: sessionKeyLength = 32; break;
            default: return result;
        }
        if (sessionPlain.size() != 1 + sessionKeyLength + 2)
        {
            return result;
        }
        std::vector<unsigned char> sessionKey(sessionKeyLength);
        std::memcpy(sessionKey.data(), &sessionPlain[1], sessionKeyLength);
        unsigned int checksum = 0;
        for (std::size_t i = 0; i < sessionKeyLength; ++i)
        {
            checksum += sessionKey[i];
        }
        const unsigned int storedChecksum = (static_cast<unsigned int>(sessionPlain[1 + sessionKeyLength]) << 8) | sessionPlain[1 + sessionKeyLength + 1];
        if ((checksum & 0xFFFF) != storedChecksum)
        {
            return result;
        }

        unsigned char seipTag = 0;
        std::size_t seipBodyLength = 0;
        if (!readPacketHeader(buf, pos, seipTag, seipBodyLength) || seipTag != PGP_TAG_SEIP)
        {
            return result;
        }
        if (pos >= buf.size() || buf[pos] != 1)
        {
            return result;
        }
        pos += 1;

        result.sessionKey = sessionKey;
        result.encLength = seipBodyLength - 1;
        result.leftoverCipher.assign(buf.begin() + pos, buf.end());
        if (result.leftoverCipher.size() > result.encLength)
        {
            result.leftoverCipher.resize(result.encLength);
        }
        result.ok = true;
        return result;
    }
    catch (...)
    {
        result.ok = false;
        return result;
    }
}
// -----------------------------------------------------------------------------

// Streams the SEIP body (CFB-decrypt + running MDC) into outputFileHandle. v1 scope: the inner
// packet must be an uncompressed Literal Data packet (tag 11) -- a compressed (tag 8) inner
// packet, as EncryptBuffer/GnuPG would produce, is not yet supported for this streaming path
// (returns NOT_IMPLEMENTED; see the pgp-engine-todo-streaming memory note for why: decompression
// would need its own nested streaming header-parsing pass, deferred).
int decryptSeipBodyStreaming(HANDLE inputFileHandle, const std::vector<unsigned char>& leftoverCipher, const std::size_t encLength, const unsigned char* sessionKey, const std::size_t sessionKeyLength, HANDLE outputFileHandle, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (encLength < 18 + 6 + 22 || leftoverCipher.size() > encLength)
        {
            return INVALID_DATA;
        }

        unsigned char zeroIv[16];
        std::memset(zeroIv, 0, 16);
        CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cfb;
        cfb.SetKeyWithIV(sessionKey, sessionKeyLength, zeroIv, 16);
        CryptoPP::SHA1 mdc;

        const std::size_t mdcHashOffset = encLength - 20;
        std::size_t cipherRemaining = encLength - leftoverCipher.size();
        std::size_t streamPos = 0;

        std::vector<unsigned char> pending(leftoverCipher.size());
        if (!leftoverCipher.empty())
        {
            cfb.ProcessData(pending.data(), leftoverCipher.data(), leftoverCipher.size());
        }
        std::size_t pendingPos = 0;

        std::vector<unsigned char> cipherReadBuf(PGP_FILE_CHUNK_SIZE);

        // Decrypts more ciphertext from the file (tracked by cipherRemaining) into `pending`
        // until at least minBytes unconsumed decrypted bytes are available, or the SEIP body
        // runs out first (a malformed/truncated file).
        auto ensurePending = [&](std::size_t minBytes) -> bool
        {
            while (pending.size() - pendingPos < minBytes)
            {
                if (cipherRemaining == 0)
                {
                    return false;
                }
                const DWORD toRead = static_cast<DWORD>((cipherRemaining < cipherReadBuf.size()) ? cipherRemaining : cipherReadBuf.size());
                DWORD bytesRead = 0;
                if (!ReadFile(inputFileHandle, cipherReadBuf.data(), toRead, &bytesRead, nullptr) || bytesRead == 0)
                {
                    return false;
                }
                cipherRemaining -= bytesRead;
                const std::size_t oldSize = pending.size();
                pending.resize(oldSize + bytesRead);
                cfb.ProcessData(&pending[oldSize], cipherReadBuf.data(), bytesRead);
            }
            return true;
        };

        // Feeds exactly `count` bytes starting at pending[pendingPos] into the running MDC
        // accumulator -- only the portion before mdcHashOffset actually counts (RFC 4880 5.13's
        // trailing 20-byte hash value is itself excluded from what it hashes) -- then advances
        // streamPos/pendingPos. Does not write anything anywhere; callers that also need these
        // bytes as content copy them out first.
        auto consumeForHash = [&](std::size_t count)
        {
            if (streamPos < mdcHashOffset)
            {
                const std::size_t hashEnd = (streamPos + count < mdcHashOffset) ? (streamPos + count) : mdcHashOffset;
                mdc.Update(&pending[pendingPos], hashEnd - streamPos);
            }
            streamPos += count;
            pendingPos += count;
        };

        if (!ensurePending(18))
        {
            return INVALID_DATA;
        }
        consumeForHash(18);

        std::size_t innerHeaderLength = 0;
        unsigned char innerTag = 0;
        std::size_t innerBodyLength = 0;
        bool innerHeaderParsed = false;
        for (std::size_t probeSize = 8; probeSize <= 512 && !innerHeaderParsed; probeSize += 8)
        {
            if (!ensurePending(probeSize))
            {
                break;
            }
            const std::vector<unsigned char> probeBuf(pending.begin() + pendingPos, pending.begin() + pendingPos + probeSize);
            std::size_t probePos = 0;
            if (readPacketHeader(probeBuf, probePos, innerTag, innerBodyLength))
            {
                innerHeaderLength = probePos;
                innerHeaderParsed = true;
            }
        }
        if (!innerHeaderParsed)
        {
            return INVALID_DATA;
        }
        if (innerTag != PGP_TAG_LITERAL_DATA)
        {
            return NOT_IMPLEMENTED;
        }
        consumeForHash(innerHeaderLength);

        if (!ensurePending(2))
        {
            return INVALID_DATA;
        }
        const unsigned char filenameLength = pending[pendingPos + 1];
        consumeForHash(2);
        if (filenameLength > 0)
        {
            if (!ensurePending(filenameLength))
            {
                return INVALID_DATA;
            }
            consumeForHash(filenameLength);
        }
        if (!ensurePending(4))
        {
            return INVALID_DATA;
        }
        consumeForHash(4);

        const std::size_t literalHeaderTotal = 2 + static_cast<std::size_t>(filenameLength) + 4;
        if (innerBodyLength < literalHeaderTotal)
        {
            return INVALID_DATA;
        }
        std::size_t contentRemaining = innerBodyLength - literalHeaderTotal;
        const unsigned long long totalContentBytes = static_cast<unsigned long long>(contentRemaining);
        unsigned long long processedBytes = 0;

        while (contentRemaining > 0)
        {
            if (!ensurePending(1))
            {
                return INVALID_DATA;
            }
            const std::size_t available = pending.size() - pendingPos;
            const std::size_t wantBytes = (contentRemaining < PGP_FILE_CHUNK_SIZE) ? contentRemaining : PGP_FILE_CHUNK_SIZE;
            const std::size_t takeNow = (available < wantBytes) ? available : wantBytes;

            if (!writeFileExact(outputFileHandle, &pending[pendingPos], static_cast<DWORD>(takeNow)))
            {
                return FILE_IO_ERROR;
            }
            consumeForHash(takeNow);
            contentRemaining -= takeNow;
            processedBytes += takeNow;

            if (onProgress)
            {
                const double percentage = totalContentBytes > 0 ? (static_cast<double>(processedBytes) / static_cast<double>(totalContentBytes)) * 100.0 : 0.0;
                if (!onProgress(processedBytes, totalContentBytes, percentage, progressUserData))
                {
                    return OPERATION_CANCELLED;
                }
            }

            if (pendingPos > PGP_FILE_CHUNK_SIZE)
            {
                pending.erase(pending.begin(), pending.begin() + pendingPos);
                pendingPos = 0;
            }
        }

        if (!ensurePending(22))
        {
            return INVALID_DATA;
        }
        const unsigned char marker0 = pending[pendingPos];
        const unsigned char marker1 = pending[pendingPos + 1];
        unsigned char storedMdc[20];
        std::memcpy(storedMdc, &pending[pendingPos + 2], 20);
        consumeForHash(22);

        if (marker0 != 0xD3 || marker1 != 0x14)
        {
            return INVALID_DATA;
        }
        unsigned char computedMdc[20];
        mdc.Final(computedMdc);
        if (std::memcmp(computedMdc, storedMdc, 20) != 0)
        {
            return INVALID_DATA;
        }

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // anonymous namespace

// ================================================================================================
// CPgpEngine
// ================================================================================================

CPgpEngine::~CPgpEngine()
{
}
// -----------------------------------------------------------------------------

CPgpEngine::CPgpEngine() : impl_(new Impl())
{
}
// -----------------------------------------------------------------------------

CPgpEngine::CPgpEngine(const int rsaKeyBits) : impl_(new Impl())
{
    impl_->rsaKeyBits = rsaKeyBits;
}
// -----------------------------------------------------------------------------

int CPgpEngine::GenerateKeyPair(const char* userId, const int userIdSize, const char* password, const int passwordSize)
{
    try
    {
        if (!impl_ || userId == nullptr || userIdSize <= 0 || password == nullptr || passwordSize <= 0)
        {
            return INVALID_ARGUMENT;
        }
        if (impl_->rsaKeyBits != 1024 && impl_->rsaKeyBits != 2048 && impl_->rsaKeyBits != 3072 && impl_->rsaKeyBits != 4096)
        {
            return INVALID_ARGUMENT;
        }

        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::RSA::PrivateKey masterPrivateKey;
        masterPrivateKey.GenerateRandomWithKeySize(rng, static_cast<unsigned int>(impl_->rsaKeyBits));
        const CryptoPP::RSA::PublicKey masterPublicKey(masterPrivateKey);

        CryptoPP::RSA::PrivateKey subkeyPrivateKey;
        subkeyPrivateKey.GenerateRandomWithKeySize(rng, static_cast<unsigned int>(impl_->rsaKeyBits));
        const CryptoPP::RSA::PublicKey subkeyPublicKey(subkeyPrivateKey);

        const std::uint32_t creationTime = static_cast<std::uint32_t>(std::time(nullptr));

        const std::vector<unsigned char> masterPubBody = buildRsaPublicKeyPacketBody(creationTime, masterPublicKey.GetModulus(), masterPublicKey.GetPublicExponent());
        unsigned char masterFingerprint[20];
        unsigned char masterKeyId[8];
        computeFingerprintAndKeyId(masterPubBody, masterFingerprint, masterKeyId);

        const std::vector<unsigned char> subkeyPubBody = buildRsaPublicKeyPacketBody(creationTime, subkeyPublicKey.GetModulus(), subkeyPublicKey.GetPublicExponent());
        unsigned char subkeyFingerprint[20];
        unsigned char subkeyKeyId[8];
        computeFingerprintAndKeyId(subkeyPubBody, subkeyFingerprint, subkeyKeyId);

        const std::vector<unsigned char> masterPubPacket = writePacket(PGP_TAG_PUBLIC_KEY, masterPubBody);

        const std::string userIdStr(userId, static_cast<std::size_t>(userIdSize));
        const std::vector<unsigned char> userIdBody(userIdStr.begin(), userIdStr.end());
        const std::vector<unsigned char> userIdPacket = writePacket(13, userIdBody);

        std::vector<unsigned char> certDocument = buildKeyHashPrefix(masterPubBody);
        {
            certDocument.push_back(0xB4);
            appendBigEndian32(certDocument, static_cast<std::uint32_t>(userIdBody.size()));
            appendAll(certDocument, userIdBody);
        }
        const std::vector<unsigned char> certSigPacket = buildSignaturePacket(masterPrivateKey, 0x13, certDocument, buildKeyFlagsSubpacket(0x03), masterKeyId);

        std::vector<unsigned char> bindDocument = buildKeyHashPrefix(masterPubBody);
        appendAll(bindDocument, buildKeyHashPrefix(subkeyPubBody));
        const std::vector<unsigned char> bindSigPacket = buildSignaturePacket(masterPrivateKey, 0x18, bindDocument, buildKeyFlagsSubpacket(0x0C), masterKeyId);

        const std::vector<unsigned char> subkeyPubPacket = writePacket(PGP_TAG_PUBLIC_SUBKEY, subkeyPubBody);

        if (certSigPacket.empty() || bindSigPacket.empty())
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> publicKeyBlock;
        appendAll(publicKeyBlock, masterPubPacket);
        appendAll(publicKeyBlock, userIdPacket);
        appendAll(publicKeyBlock, certSigPacket);
        appendAll(publicKeyBlock, subkeyPubPacket);
        appendAll(publicKeyBlock, bindSigPacket);

        const std::vector<unsigned char> masterSecretBody = buildSecretKeyPacketBody(masterPubBody, masterPrivateKey, password, passwordSize);
        const std::vector<unsigned char> subkeySecretBody = buildSecretKeyPacketBody(subkeyPubBody, subkeyPrivateKey, password, passwordSize);
        if (masterSecretBody.empty() || subkeySecretBody.empty())
        {
            return UNEXPECTED_ERROR;
        }
        const std::vector<unsigned char> masterSecretPacket = writePacket(PGP_TAG_SECRET_KEY, masterSecretBody);
        const std::vector<unsigned char> subkeySecretPacket = writePacket(PGP_TAG_SECRET_SUBKEY, subkeySecretBody);

        std::vector<unsigned char> secretKeyBlock;
        appendAll(secretKeyBlock, masterSecretPacket);
        appendAll(secretKeyBlock, userIdPacket);
        appendAll(secretKeyBlock, certSigPacket);
        appendAll(secretKeyBlock, subkeySecretPacket);
        appendAll(secretKeyBlock, bindSigPacket);

        impl_->ownMasterPrivateKey = masterPrivateKey;
        impl_->ownMasterPublicKey = masterPublicKey;
        impl_->ownSubkeyPrivateKey = subkeyPrivateKey;
        impl_->ownSubkeyPublicKey = subkeyPublicKey;
        std::memcpy(impl_->ownMasterKeyId, masterKeyId, 8);
        std::memcpy(impl_->ownSubkeyKeyId, subkeyKeyId, 8);
        CryptoPP::SHA256().CalculateDigest(impl_->passwordCheckHash, reinterpret_cast<const CryptoPP::byte*>(password), static_cast<std::size_t>(passwordSize));

        impl_->ownPublicKeyArmored = armorEncode("PGP PUBLIC KEY BLOCK", publicKeyBlock);
        impl_->ownSecretKeyArmored = armorEncode("PGP PRIVATE KEY BLOCK", secretKeyBlock);
        impl_->ownKeyGenerated = true;

        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::GetPublicKeyArmoredSize(void) const
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated)
        {
            return 0;
        }
        return static_cast<int>(impl_->ownPublicKeyArmored.size());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::GetSecretKeyArmoredSize(void) const
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated)
        {
            return 0;
        }
        return static_cast<int>(impl_->ownSecretKeyArmored.size());
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::ExportPublicKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        const std::string& armored = impl_->ownPublicKeyArmored;
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armored.size()))
        {
            *outputBufferSize = static_cast<int>(armored.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, armored.data(), armored.size());
        *outputBufferSize = static_cast<int>(armored.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::ExportSecretKeyArmored(const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        const std::string& armored = impl_->ownSecretKeyArmored;
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armored.size()))
        {
            *outputBufferSize = static_cast<int>(armored.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, armored.data(), armored.size());
        *outputBufferSize = static_cast<int>(armored.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::GetKeyId(char* outputBuffer, const int outputBufferCapacity) const
{
    try
    {
        if (!impl_ || outputBuffer == nullptr || outputBufferCapacity < 17)
        {
            return BUFFER_TOO_SMALL;
        }
        if (!impl_->ownKeyGenerated)
        {
            outputBuffer[0] = '\0';
            return NO_ERROR;
        }
        static const char* hexDigits = "0123456789ABCDEF";
        for (int i = 0; i < 8; ++i)
        {
            outputBuffer[i * 2] = hexDigits[(impl_->ownMasterKeyId[i] >> 4) & 0xF];
            outputBuffer[i * 2 + 1] = hexDigits[impl_->ownMasterKeyId[i] & 0xF];
        }
        outputBuffer[16] = '\0';
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::ImportPeerPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize)
{
    try
    {
        if (!impl_ || keyBlockBuffer == nullptr || keyBlockBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }

        std::vector<unsigned char> binary;
        if (keyBlockBufferSize >= 5 && std::memcmp(keyBlockBuffer, "-----", 5) == 0)
        {
            const std::string armored(reinterpret_cast<const char*>(keyBlockBuffer), static_cast<std::size_t>(keyBlockBufferSize));
            std::string blockType;
            if (!armorDecode(armored, blockType, binary))
            {
                return INVALID_DATA;
            }
        }
        else
        {
            binary.assign(keyBlockBuffer, keyBlockBuffer + keyBlockBufferSize);
        }

        CryptoPP::RSA::PublicKey masterKey;
        CryptoPP::RSA::PublicKey subkey;
        unsigned char masterKeyId[8];
        unsigned char subkeyKeyId[8];
        std::memset(masterKeyId, 0, 8);
        std::memset(subkeyKeyId, 0, 8);
        bool haveMaster = false;
        bool haveSubkey = false;

        std::size_t pos = 0;
        while (pos < binary.size())
        {
            unsigned char tag = 0;
            std::size_t bodyLength = 0;
            if (!readPacketHeader(binary, pos, tag, bodyLength) || pos + bodyLength > binary.size())
            {
                break;
            }
            const std::vector<unsigned char> body(binary.begin() + pos, binary.begin() + pos + bodyLength);
            pos += bodyLength;

            if (tag == PGP_TAG_PUBLIC_KEY || tag == PGP_TAG_PUBLIC_SUBKEY)
            {
                CryptoPP::Integer n;
                CryptoPP::Integer e;
                unsigned char keyId[8];
                if (!parseRsaPublicKeyPacketBody(body, n, e, keyId))
                {
                    continue;
                }
                CryptoPP::RSA::PublicKey key;
                key.Initialize(n, e);
                if (tag == PGP_TAG_PUBLIC_KEY && !haveMaster)
                {
                    masterKey = key;
                    std::memcpy(masterKeyId, keyId, 8);
                    haveMaster = true;
                }
                else if (tag == PGP_TAG_PUBLIC_SUBKEY && !haveSubkey)
                {
                    subkey = key;
                    std::memcpy(subkeyKeyId, keyId, 8);
                    haveSubkey = true;
                }
            }
        }

        if (!haveMaster)
        {
            return INVALID_DATA;
        }

        impl_->peerMasterPublicKey = masterKey;
        std::memcpy(impl_->peerMasterKeyId, masterKeyId, 8);
        if (haveSubkey)
        {
            impl_->peerSubkeyPublicKey = subkey;
            std::memcpy(impl_->peerSubkeyKeyId, subkeyKeyId, 8);
        }
        else
        {
            impl_->peerSubkeyPublicKey = masterKey;
            std::memcpy(impl_->peerSubkeyKeyId, masterKeyId, 8);
        }
        impl_->peerKeyImported = true;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::GetPeerKeyId(char* outputBuffer, const int outputBufferCapacity) const
{
    try
    {
        if (!impl_ || outputBuffer == nullptr || outputBufferCapacity < 17)
        {
            return BUFFER_TOO_SMALL;
        }
        if (!impl_->peerKeyImported)
        {
            outputBuffer[0] = '\0';
            return NO_ERROR;
        }
        static const char* hexDigits = "0123456789ABCDEF";
        for (int i = 0; i < 8; ++i)
        {
            outputBuffer[i * 2] = hexDigits[(impl_->peerMasterKeyId[i] >> 4) & 0xF];
            outputBuffer[i * 2 + 1] = hexDigits[impl_->peerMasterKeyId[i] & 0xF];
        }
        outputBuffer[16] = '\0';
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::EncryptBuffer(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->peerKeyImported || outputBufferSize == nullptr || inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        std::vector<unsigned char> message;
        if (!buildEncryptedMessage(impl_->peerSubkeyPublicKey, impl_->peerSubkeyKeyId, inputBuffer, static_cast<std::size_t>(inputBufferSize), message))
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(message.size()))
        {
            *outputBufferSize = static_cast<int>(message.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, message.data(), message.size());
        *outputBufferSize = static_cast<int>(message.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::EncryptStringArmored(const char* inputString, const int inputStringSize, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->peerKeyImported || outputBufferSize == nullptr || inputStringSize < 0 || (inputStringSize > 0 && inputString == nullptr))
        {
            return INVALID_ARGUMENT;
        }

        const unsigned char* inputBytes = reinterpret_cast<const unsigned char*>(inputString);
        std::vector<unsigned char> message;
        if (!buildEncryptedMessage(impl_->peerSubkeyPublicKey, impl_->peerSubkeyKeyId, inputBytes, static_cast<std::size_t>(inputStringSize), message))
        {
            return UNEXPECTED_ERROR;
        }

        const std::string armored = armorEncode("PGP MESSAGE", message);
        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(armored.size()))
        {
            *outputBufferSize = static_cast<int>(armored.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, armored.data(), armored.size());
        *outputBufferSize = static_cast<int>(armored.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::DecryptBuffer(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || password == nullptr || passwordSize <= 0 || inputBuffer == nullptr || inputBufferSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!checkPasswordHash(impl_->passwordCheckHash, password, passwordSize))
        {
            return INVALID_ARGUMENT;
        }

        const std::vector<unsigned char> message(inputBuffer, inputBuffer + inputBufferSize);
        std::vector<unsigned char> plaintext;
        if (!parseAndDecryptMessage(impl_->ownSubkeyPrivateKey, message, plaintext))
        {
            return INVALID_DATA;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(plaintext.size()))
        {
            *outputBufferSize = static_cast<int>(plaintext.size());
            return BUFFER_TOO_SMALL;
        }
        if (!plaintext.empty())
        {
            std::memcpy(outputBuffer, plaintext.data(), plaintext.size());
        }
        *outputBufferSize = static_cast<int>(plaintext.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::DecryptStringArmored(const char* password, const int passwordSize, const char* inputString, const int inputStringSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || password == nullptr || passwordSize <= 0 || inputString == nullptr || inputStringSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!checkPasswordHash(impl_->passwordCheckHash, password, passwordSize))
        {
            return INVALID_ARGUMENT;
        }

        const std::string armored(inputString, static_cast<std::size_t>(inputStringSize));
        std::string blockType;
        std::vector<unsigned char> message;
        if (!armorDecode(armored, blockType, message))
        {
            return INVALID_DATA;
        }

        std::vector<unsigned char> plaintext;
        if (!parseAndDecryptMessage(impl_->ownSubkeyPrivateKey, message, plaintext))
        {
            return INVALID_DATA;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(plaintext.size()))
        {
            *outputBufferSize = static_cast<int>(plaintext.size());
            return BUFFER_TOO_SMALL;
        }
        if (!plaintext.empty())
        {
            std::memcpy(outputBuffer, plaintext.data(), plaintext.size());
        }
        *outputBufferSize = static_cast<int>(plaintext.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::SignBuffer(const char* password, const int passwordSize, const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, unsigned char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || password == nullptr || passwordSize <= 0 || inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr) || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!checkPasswordHash(impl_->passwordCheckHash, password, passwordSize))
        {
            return INVALID_ARGUMENT;
        }

        const std::vector<unsigned char> documentData(inputBuffer, inputBuffer + inputBufferSize);
        const std::vector<unsigned char> sigPacket = buildSignaturePacket(impl_->ownMasterPrivateKey, 0x00, documentData, std::vector<unsigned char>(), impl_->ownMasterKeyId);
        if (sigPacket.empty())
        {
            return UNEXPECTED_ERROR;
        }

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(sigPacket.size()))
        {
            *outputBufferSize = static_cast<int>(sigPacket.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, sigPacket.data(), sigPacket.size());
        *outputBufferSize = static_cast<int>(sigPacket.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::VerifyBuffer(const unsigned char* inputBuffer, const int inputBufferSize, const unsigned char* signatureBuffer, const int signatureBufferSize, bool* isValid)
{
    try
    {
        if (!impl_ || !impl_->peerKeyImported || isValid == nullptr || inputBufferSize < 0 || (inputBufferSize > 0 && inputBuffer == nullptr) || signatureBuffer == nullptr || signatureBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }

        const std::vector<unsigned char> documentData(inputBuffer, inputBuffer + inputBufferSize);
        const std::vector<unsigned char> sigPacketBytes(signatureBuffer, signatureBuffer + signatureBufferSize);

        bool verified = false;
        if (!verifySignaturePacket(impl_->peerMasterPublicKey, documentData, sigPacketBytes, &verified))
        {
            return INVALID_DATA;
        }

        *isValid = verified;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::ClearSignString(const char* password, const int passwordSize, const char* inputString, const int inputStringSize, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || password == nullptr || passwordSize <= 0 || inputString == nullptr || inputStringSize < 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!checkPasswordHash(impl_->passwordCheckHash, password, passwordSize))
        {
            return INVALID_ARGUMENT;
        }

        const std::string text(inputString, static_cast<std::size_t>(inputStringSize));
        const std::vector<std::string> lines = splitAndCanonicalizeLines(text);

        // RFC 4880 section 7.1: every line is hashed with a trailing CRLF EXCEPT the last one,
        // which has no line ending added (matches GnuPG's own clear-sign hashing -- verified
        // against real gpg.exe, which reports BAD signature if a trailing CRLF is added here).
        std::vector<unsigned char> documentData;
        for (std::size_t i = 0; i < lines.size(); ++i)
        {
            documentData.insert(documentData.end(), lines[i].begin(), lines[i].end());
            if (i + 1 < lines.size())
            {
                documentData.push_back('\r');
                documentData.push_back('\n');
            }
        }

        const std::vector<unsigned char> sigPacket = buildSignaturePacket(impl_->ownMasterPrivateKey, 0x01, documentData, std::vector<unsigned char>(), impl_->ownMasterKeyId);
        if (sigPacket.empty())
        {
            return UNEXPECTED_ERROR;
        }

        std::string out = "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\n";
        for (std::size_t i = 0; i < lines.size(); ++i)
        {
            if (!lines[i].empty() && lines[i][0] == '-')
            {
                out += "- ";
            }
            out += lines[i];
            out += "\r\n";
        }
        out += armorEncode("PGP SIGNATURE", sigPacket);

        if (outputBuffer == nullptr || outputBufferCapacity < static_cast<int>(out.size()))
        {
            *outputBufferSize = static_cast<int>(out.size());
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, out.data(), out.size());
        *outputBufferSize = static_cast<int>(out.size());
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::VerifyClearSignedString(const char* clearSignedString, const int clearSignedStringSize, bool* isValid)
{
    try
    {
        if (!impl_ || !impl_->peerKeyImported || clearSignedString == nullptr || clearSignedStringSize <= 0 || isValid == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        const std::string text(clearSignedString, static_cast<std::size_t>(clearSignedStringSize));
        const std::size_t beginPos = text.find("-----BEGIN PGP SIGNED MESSAGE-----");
        if (beginPos == std::string::npos)
        {
            return INVALID_DATA;
        }

        const std::size_t blankLf = text.find("\n\n", beginPos);
        const std::size_t blankCrLf = text.find("\r\n\r\n", beginPos);
        std::size_t bodyStart;
        if (blankCrLf != std::string::npos && (blankLf == std::string::npos || blankCrLf <= blankLf))
        {
            bodyStart = blankCrLf + 4;
        }
        else if (blankLf != std::string::npos)
        {
            bodyStart = blankLf + 2;
        }
        else
        {
            return INVALID_DATA;
        }

        const std::size_t sigBeginPos = text.find("-----BEGIN PGP SIGNATURE-----", bodyStart);
        if (sigBeginPos == std::string::npos)
        {
            return INVALID_DATA;
        }

        const std::string bodySection = text.substr(bodyStart, sigBeginPos - bodyStart);
        std::vector<std::string> rawLines;
        {
            std::string current;
            for (std::size_t i = 0; i < bodySection.size(); ++i)
            {
                const char c = bodySection[i];
                if (c == '\n')
                {
                    rawLines.push_back(current);
                    current.clear();
                }
                else if (c != '\r')
                {
                    current += c;
                }
            }
            if (!current.empty())
            {
                rawLines.push_back(current);
            }
        }
        if (!rawLines.empty() && rawLines[rawLines.size() - 1].empty())
        {
            rawLines.pop_back();
        }

        std::vector<unsigned char> documentData;
        for (std::size_t i = 0; i < rawLines.size(); ++i)
        {
            std::string line = rawLines[i];
            if (line.size() >= 2 && line[0] == '-' && line[1] == ' ')
            {
                line = line.substr(2);
            }
            while (!line.empty() && (line[line.size() - 1] == ' ' || line[line.size() - 1] == '\t'))
            {
                line.erase(line.size() - 1);
            }
            documentData.insert(documentData.end(), line.begin(), line.end());
            if (i + 1 < rawLines.size())
            {
                documentData.push_back('\r');
                documentData.push_back('\n');
            }
        }

        const std::string sigSection = text.substr(sigBeginPos);
        std::string blockType;
        std::vector<unsigned char> sigPacketBytes;
        if (!armorDecode(sigSection, blockType, sigPacketBytes))
        {
            return INVALID_DATA;
        }

        bool verified = false;
        if (!verifySignaturePacket(impl_->peerMasterPublicKey, documentData, sigPacketBytes, &verified))
        {
            return INVALID_DATA;
        }

        *isValid = verified;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::EncryptFile(const char* inputFilePath, const char* outputFilePath, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || !impl_->peerKeyImported || inputFilePath == nullptr || outputFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        std::wstring wideInputPath;
        std::wstring wideOutputPath;
        if (!convertUtf8PathToWide(inputFilePath, wideInputPath) || !convertUtf8PathToWide(outputFilePath, wideOutputPath))
        {
            return INVALID_ARGUMENT;
        }

        const HANDLE rawInputHandle = CreateFileW(wideInputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawInputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> inputHandle(rawInputHandle, &CloseHandle);

        LARGE_INTEGER inputFileSize;
        inputFileSize.QuadPart = 0;
        if (!GetFileSizeEx(rawInputHandle, &inputFileSize) || inputFileSize.QuadPart < 0)
        {
            return FILE_IO_ERROR;
        }
        const unsigned long long fileSize = static_cast<unsigned long long>(inputFileSize.QuadPart);

        const HANDLE rawOutputHandle = CreateFileW(wideOutputPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawOutputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> outputHandle(rawOutputHandle, &CloseHandle);

        const int status = encryptFileStreaming(impl_->peerSubkeyPublicKey, impl_->peerSubkeyKeyId, rawInputHandle, fileSize, rawOutputHandle, onProgress, progressUserData);
        if (status != NO_ERROR)
        {
            outputHandle.reset();
            DeleteFileW(wideOutputPath.c_str());
        }
        return status;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::DecryptFile(const char* password, const int passwordSize, const char* inputFilePath, const char* outputFilePath, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || password == nullptr || passwordSize <= 0 || inputFilePath == nullptr || outputFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!checkPasswordHash(impl_->passwordCheckHash, password, passwordSize))
        {
            return INVALID_ARGUMENT;
        }

        std::wstring wideInputPath;
        std::wstring wideOutputPath;
        if (!convertUtf8PathToWide(inputFilePath, wideInputPath) || !convertUtf8PathToWide(outputFilePath, wideOutputPath))
        {
            return INVALID_ARGUMENT;
        }
        const std::wstring wideTempPath = wideOutputPath + L".pgptmp";

        const HANDLE rawInputHandle = CreateFileW(wideInputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawInputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> inputHandle(rawInputHandle, &CloseHandle);

        const DecryptFileHeader header = parseEncryptedFileHeader(rawInputHandle, impl_->ownSubkeyPrivateKey);
        if (!header.ok)
        {
            return INVALID_DATA;
        }

        const HANDLE rawTempHandle = CreateFileW(wideTempPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawTempHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> tempHandle(rawTempHandle, &CloseHandle);

        const int status = decryptSeipBodyStreaming(rawInputHandle, header.leftoverCipher, header.encLength,
                                                     header.sessionKey.data(), header.sessionKey.size(),
                                                     rawTempHandle, onProgress, progressUserData);
        tempHandle.reset();
        if (status != NO_ERROR)
        {
            DeleteFileW(wideTempPath.c_str());
            return status;
        }

        DeleteFileW(wideOutputPath.c_str());
        if (!MoveFileExW(wideTempPath.c_str(), wideOutputPath.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            DeleteFileW(wideTempPath.c_str());
            return FILE_IO_ERROR;
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::SignFile(const char* password, const int passwordSize, const char* inputFilePath, const char* signatureFilePath, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || password == nullptr || passwordSize <= 0 || inputFilePath == nullptr || signatureFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!checkPasswordHash(impl_->passwordCheckHash, password, passwordSize))
        {
            return INVALID_ARGUMENT;
        }

        std::wstring wideInputPath;
        std::wstring wideSignaturePath;
        if (!convertUtf8PathToWide(inputFilePath, wideInputPath) || !convertUtf8PathToWide(signatureFilePath, wideSignaturePath))
        {
            return INVALID_ARGUMENT;
        }

        const HANDLE rawInputHandle = CreateFileW(wideInputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawInputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> inputHandle(rawInputHandle, &CloseHandle);

        LARGE_INTEGER inputFileSize;
        inputFileSize.QuadPart = 0;
        if (!GetFileSizeEx(rawInputHandle, &inputFileSize) || inputFileSize.QuadPart < 0)
        {
            return FILE_IO_ERROR;
        }
        const unsigned long long fileSize = static_cast<unsigned long long>(inputFileSize.QuadPart);

        std::vector<unsigned char> signaturePacket;
        const int status = signFileStreaming(impl_->ownMasterPrivateKey, rawInputHandle, fileSize, impl_->ownMasterKeyId, onProgress, progressUserData, signaturePacket);
        if (status != NO_ERROR)
        {
            return status;
        }

        const HANDLE rawSigHandle = CreateFileW(wideSignaturePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawSigHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> sigHandle(rawSigHandle, &CloseHandle);
        if (!writeFileExact(rawSigHandle, signaturePacket.data(), static_cast<DWORD>(signaturePacket.size())))
        {
            sigHandle.reset();
            DeleteFileW(wideSignaturePath.c_str());
            return FILE_IO_ERROR;
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::VerifyFile(const char* inputFilePath, const char* signatureFilePath, bool* isValid, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || !impl_->peerKeyImported || inputFilePath == nullptr || signatureFilePath == nullptr || isValid == nullptr)
        {
            return INVALID_ARGUMENT;
        }

        std::wstring wideInputPath;
        std::wstring wideSignaturePath;
        if (!convertUtf8PathToWide(inputFilePath, wideInputPath) || !convertUtf8PathToWide(signatureFilePath, wideSignaturePath))
        {
            return INVALID_ARGUMENT;
        }

        std::vector<unsigned char> signaturePacketBytes;
        {
            const HANDLE rawSigHandle = CreateFileW(wideSignaturePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (rawSigHandle == INVALID_HANDLE_VALUE)
            {
                return FILE_IO_ERROR;
            }
            std::unique_ptr<void, decltype(&CloseHandle)> sigHandle(rawSigHandle, &CloseHandle);

            LARGE_INTEGER sigSize;
            sigSize.QuadPart = 0;
            if (!GetFileSizeEx(rawSigHandle, &sigSize) || sigSize.QuadPart < 0 || sigSize.QuadPart > 65536)
            {
                return FILE_IO_ERROR;
            }
            signaturePacketBytes.resize(static_cast<std::size_t>(sigSize.QuadPart));
            if (!signaturePacketBytes.empty() && !readFileExact(rawSigHandle, &signaturePacketBytes[0], static_cast<DWORD>(signaturePacketBytes.size())))
            {
                return FILE_IO_ERROR;
            }
        }

        const HANDLE rawInputHandle = CreateFileW(wideInputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawInputHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> inputHandle(rawInputHandle, &CloseHandle);

        LARGE_INTEGER inputFileSize;
        inputFileSize.QuadPart = 0;
        if (!GetFileSizeEx(rawInputHandle, &inputFileSize) || inputFileSize.QuadPart < 0)
        {
            return FILE_IO_ERROR;
        }
        const unsigned long long fileSize = static_cast<unsigned long long>(inputFileSize.QuadPart);

        return verifyFileStreaming(impl_->peerMasterPublicKey, rawInputHandle, fileSize, signaturePacketBytes, isValid, onProgress, progressUserData);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

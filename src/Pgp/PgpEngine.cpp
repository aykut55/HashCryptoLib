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
#include "cryptopp890/xed25519.h"
#include "cryptopp890/zdeflate.h"
#include "cryptopp890/zinflate.h"
#include "cryptopp890/zlib.h"

#include <algorithm>
#include <array>
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
    const unsigned char PGP_TAG_SKESK           = 3;
    const unsigned char PGP_TAG_ONE_PASS_SIG    = 4;
    const unsigned char PGP_TAG_SECRET_KEY      = 5;
    const unsigned char PGP_TAG_PUBLIC_KEY      = 6;
    const unsigned char PGP_TAG_SECRET_SUBKEY   = 7;
    const unsigned char PGP_TAG_COMPRESSED_DATA = 8;
    const unsigned char PGP_TAG_SED             = 9;
    const unsigned char PGP_TAG_LITERAL_DATA    = 11;
    const unsigned char PGP_TAG_PUBLIC_SUBKEY   = 14;
    const unsigned char PGP_TAG_SEIP            = 18;
    const unsigned char PGP_TAG_AEAD            = 20;
}

// One encryption-only recipient (RFC 4880 Public-Key Encrypted Session Key, tag 1) -- either an
// RSA key or an Ed25519/X25519 identity's X25519 encryption subkey, each recipient's own algorithm
// detected independently at import time (see parsePublicKeyBlock below). Used both for the primary
// peer's encryption subkey (impl_->peerSubkeyAlgorithm/peerSubkeyPublicKey/peerX25519PublicKey/
// peerSubkeyKeyId/peerSubkeyFingerprint fields below, kept as separate Impl members for backward
// compatibility with the pre-multi-recipient single-peer field layout) and for every
// ImportAdditionalRecipientPublicKey() addition (impl_->additionalRecipients below).
struct PgpEncryptionRecipient
{
    PgpKeyAlgorithm algorithm;
    CryptoPP::RSA::PublicKey rsaPublicKey;
    unsigned char rsaKeyId[8];
    unsigned char x25519PublicKey[32];
    unsigned char x25519KeyId[8];
    unsigned char x25519Fingerprint[20]; // needed as-is by the ECDH KDF's "param" (RFC 6637 section 7).

    PgpEncryptionRecipient() : algorithm(PGP_KEY_ALGORITHM_RSA)
    {
        std::memset(rsaKeyId, 0, 8);
        std::memset(x25519PublicKey, 0, 32);
        std::memset(x25519KeyId, 0, 8);
        std::memset(x25519Fingerprint, 0, 20);
    }
};

struct CPgpEngine::Impl
{
    PgpKeyAlgorithm keyAlgorithm; // this instance's OWN identity algorithm; fixed at construction.
    int rsaKeyBits;
    bool ownKeyGenerated;

    // Own key material -- only the fields matching keyAlgorithm are ever populated/used.
    CryptoPP::RSA::PrivateKey ownMasterPrivateKey;
    CryptoPP::RSA::PublicKey  ownMasterPublicKey;
    CryptoPP::RSA::PrivateKey ownSubkeyPrivateKey;
    CryptoPP::RSA::PublicKey  ownSubkeyPublicKey;
    unsigned char ownEd25519PrivateKey[32];
    unsigned char ownEd25519PublicKey[32];
    unsigned char ownX25519PrivateKey[32];
    unsigned char ownX25519PublicKey[32];

    unsigned char ownMasterKeyId[8];
    unsigned char ownSubkeyKeyId[8];
    unsigned char ownSubkeyFingerprint[20]; // needed by the ECDH KDF when decrypting a PKESK addressed to our own X25519 encryption subkey.
    unsigned char passwordCheckHash[32];
    std::string ownPublicKeyArmored;
    std::string ownSecretKeyArmored;
    std::uint32_t keyCreationTime;   // seconds since epoch, as embedded in the exported public key packet -- reused by RevokeKeyArmored so its recomputed public-key-packet body byte-matches the one already exported (and therefore fingerprints/Key-IDs the same).
    std::uint32_t keyExpirationSeconds; // 0 = never expires; otherwise seconds after keyCreationTime, as set by GenerateKeyPair's expiration overload.

    bool peerKeyImported;
    PgpKeyAlgorithm peerMasterAlgorithm; // algorithm of the imported peer's MASTER (verify) key.
    PgpKeyAlgorithm peerSubkeyAlgorithm; // algorithm of the imported peer's ENCRYPTION SUBKEY -- independent of peerMasterAlgorithm in principle, though every identity this engine or GnuPG's own "ed25519" default produces keeps both in the same family.
    CryptoPP::RSA::PublicKey peerMasterPublicKey;
    CryptoPP::RSA::PublicKey peerSubkeyPublicKey;
    unsigned char peerEd25519PublicKey[32];
    unsigned char peerX25519PublicKey[32];
    unsigned char peerMasterKeyId[8];
    unsigned char peerSubkeyKeyId[8];
    unsigned char peerSubkeyFingerprint[20]; // needed by the ECDH KDF when peerSubkeyAlgorithm==ED25519_X25519.

    // ImportAdditionalRecipientPublicKey() additions -- encryption-only, never used for verify.
    std::vector<PgpEncryptionRecipient> additionalRecipients;

    Impl() : keyAlgorithm(PGP_KEY_ALGORITHM_RSA), rsaKeyBits(2048), ownKeyGenerated(false), keyCreationTime(0), keyExpirationSeconds(0),
             peerKeyImported(false), peerMasterAlgorithm(PGP_KEY_ALGORITHM_RSA), peerSubkeyAlgorithm(PGP_KEY_ALGORITHM_RSA)
    {
        std::memset(ownEd25519PrivateKey, 0, 32);
        std::memset(ownEd25519PublicKey, 0, 32);
        std::memset(ownX25519PrivateKey, 0, 32);
        std::memset(ownX25519PublicKey, 0, 32);
        std::memset(ownMasterKeyId, 0, 8);
        std::memset(ownSubkeyKeyId, 0, 8);
        std::memset(ownSubkeyFingerprint, 0, 20);
        std::memset(passwordCheckHash, 0, 32);
        std::memset(peerEd25519PublicKey, 0, 32);
        std::memset(peerX25519PublicKey, 0, 32);
        std::memset(peerMasterKeyId, 0, 8);
        std::memset(peerSubkeyKeyId, 0, 8);
        std::memset(peerSubkeyFingerprint, 0, 20);
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
// it defaults to data.size() for ordinary top-level parsing.
//
// New-format PARTIAL body lengths (first length byte 224-254, RFC 4880 section 4.2.2.4 -- a body
// split into a sequence of power-of-two-sized chunks, each preceded by its own length octet(s),
// terminated by one final chunk carrying an ordinary definite length) are reported ONLY to callers
// that opt in by passing a non-null isPartialLength. Those callers get bodyLength = the FIRST
// chunk's size together with *isPartialLength = true, and take on the job of walking the rest of
// the chunk sequence themselves (see decodeNewFormatBodyLength/reassemblePartialBodyLengthRange/
// dechunkPartialBody below, which do exactly that). Every caller that passes nullptr -- i.e. every
// caller that wants one already-contiguous packet body -- keeps the original behavior of rejecting
// such a header outright, so definite-length and old-format input is parsed byte-for-byte the way
// it always was.
bool readPacketHeader(const std::vector<unsigned char>& data, std::size_t& pos, unsigned char& tag, std::size_t& bodyLength, const std::size_t dataEnd = static_cast<std::size_t>(-1), bool* isPartialLength = nullptr)
{
    try
    {
        if (isPartialLength != nullptr)
        {
            *isPartialLength = false;
        }

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
            else if (lenFirst < 255)
            {
                // Partial body length (RFC 4880 section 4.2.2.4) -- opt-in only, see the comment
                // above: bodyLength is just this FIRST chunk, not the whole packet body.
                if (isPartialLength == nullptr)
                {
                    return false;
                }
                bodyLength = static_cast<std::size_t>(1) << (lenFirst & 0x1F);
                *isPartialLength = true;
                pos += 1;
            }
            else
            {
                if (pos + 4 >= data.size())
                {
                    return false;
                }
                bodyLength = (static_cast<std::size_t>(data[pos + 1]) << 24) | (static_cast<std::size_t>(data[pos + 2]) << 16) |
                             (static_cast<std::size_t>(data[pos + 3]) << 8)  |  static_cast<std::size_t>(data[pos + 4]);
                pos += 5;
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

// How many octets the new-format body-length header starting with `first` occupies (RFC 4880
// section 4.2.2): 1 for a one-octet length (0-191) or a partial length (224-254), 2 for a
// two-octet length (192-223), 5 for the five-octet form (255).
std::size_t newFormatBodyLengthHeaderSize(const unsigned char first)
{
    try
    {
        if (first < 192)
        {
            return 1;
        }
        if (first < 224)
        {
            return 2;
        }
        if (first < 255)
        {
            return 1;
        }
        return 5;
    }
    catch (...)
    {
        return 5;
    }
}
// -----------------------------------------------------------------------------

// Decodes ONE new-format body-length header (RFC 4880 section 4.2.2) from `header` -- the bare
// length octet(s) with no packet tag octet in front, which is exactly what precedes every partial
// body chunk after the first one (section 4.2.2.4). Returns false when availableSize is smaller
// than the encoding the first octet announces, so an incremental caller can simply wait for more
// bytes. isPartial says whether yet another chunk follows this one (first octet 224-254) or this
// is the packet's final, definite-length chunk.
bool decodeNewFormatBodyLength(const unsigned char* header, const std::size_t availableSize, std::size_t& headerSize, std::size_t& chunkLength, bool& isPartial)
{
    try
    {
        if (header == nullptr || availableSize == 0)
        {
            return false;
        }

        const unsigned char first = header[0];
        if (first < 192)
        {
            headerSize = 1;
            chunkLength = first;
            isPartial = false;
            return true;
        }
        if (first < 224)
        {
            if (availableSize < 2)
            {
                return false;
            }
            headerSize = 2;
            chunkLength = (static_cast<std::size_t>(first - 192) << 8) + static_cast<std::size_t>(header[1]) + 192;
            isPartial = false;
            return true;
        }
        if (first < 255)
        {
            headerSize = 1;
            chunkLength = static_cast<std::size_t>(1) << (first & 0x1F);
            isPartial = true;
            return true;
        }
        if (availableSize < 5)
        {
            return false;
        }
        headerSize = 5;
        chunkLength = (static_cast<std::size_t>(header[1]) << 24) | (static_cast<std::size_t>(header[2]) << 16) |
                      (static_cast<std::size_t>(header[3]) << 8)  |  static_cast<std::size_t>(header[4]);
        isPartial = false;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Strips the per-chunk length headers of a new-format partial-body-length packet body (RFC 4880
// section 4.2.2.4) out of `raw`, appending the de-framed content octets to `content`. Consumes as
// much of `raw` as it can and leaves any incomplete trailing chunk header in place for the next
// call, so a streaming reader can keep feeding it whatever bytes have arrived so far. chunkRemaining
// / finalChunk carry the chunk-sequence state across calls: the caller seeds them from the packet's
// own (first) header, and finalChunk turns true once the terminating definite-length chunk has been
// entered.
bool dechunkPartialBody(std::vector<unsigned char>& raw, std::size_t& chunkRemaining, bool& finalChunk, std::vector<unsigned char>& content)
{
    try
    {
        std::size_t pos = 0;
        while (pos < raw.size())
        {
            if (chunkRemaining > 0)
            {
                const std::size_t available = raw.size() - pos;
                const std::size_t take = (chunkRemaining < available) ? chunkRemaining : available;
                content.insert(content.end(), raw.begin() + pos, raw.begin() + pos + take);
                pos += take;
                chunkRemaining -= take;
                continue;
            }
            if (finalChunk)
            {
                break;
            }
            const std::size_t needed = newFormatBodyLengthHeaderSize(raw[pos]);
            if (raw.size() - pos < needed)
            {
                break;
            }
            std::size_t headerSize = 0;
            std::size_t chunkLength = 0;
            bool isPartial = false;
            if (!decodeNewFormatBodyLength(&raw[pos], raw.size() - pos, headerSize, chunkLength, isPartial))
            {
                return false;
            }
            pos += headerSize;
            chunkRemaining = chunkLength;
            finalChunk = !isPartial;
        }
        raw.erase(raw.begin(), raw.begin() + pos);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Rewrites data[begin, end) -- a sequence of whole OpenPGP packets already held in one contiguous
// buffer -- into `out`, splicing every new-format partial-body-length packet (RFC 4880 section
// 4.2.2.4) back together into a single ordinary definite-length new-format packet, so all the
// buffer-based readers in this file can keep treating a packet body as one contiguous range.
// Packets that are not partial-length framed are copied through byte-for-byte, header included.
// Returns true ONLY when at least one partial-length packet was actually found and rewritten; on
// false `out` is meaningless and the caller must keep using the original bytes -- that is what
// guarantees definite-length/old-format input never even sees a copy, let alone a behavior change.
bool reassemblePartialBodyLengthRange(const std::vector<unsigned char>& data, const std::size_t begin, const std::size_t end, std::vector<unsigned char>& out)
{
    try
    {
        if (begin > end || end > data.size())
        {
            return false;
        }

        out.clear();
        bool rewroteAny = false;
        std::size_t pos = begin;
        while (pos < end)
        {
            const std::size_t headerStart = pos;
            unsigned char tag = 0;
            std::size_t bodyLength = 0;
            bool isPartial = false;
            if (!readPacketHeader(data, pos, tag, bodyLength, end, &isPartial))
            {
                // Trailing bytes that are not a packet header at all (the armor decoder's own
                // padding, a truncated tail, ...): pass them through untouched, exactly as the
                // original buffer would have presented them.
                out.insert(out.end(), data.begin() + headerStart, data.begin() + end);
                pos = end;
                break;
            }

            if (!isPartial)
            {
                const std::size_t remaining = end - pos;
                const std::size_t bodyEnd = (bodyLength > remaining) ? end : (pos + bodyLength);
                out.insert(out.end(), data.begin() + headerStart, data.begin() + bodyEnd);
                pos = bodyEnd;
                continue;
            }

            std::vector<unsigned char> body;
            std::size_t chunkLength = bodyLength;
            bool moreChunks = true;
            while (true)
            {
                if (chunkLength > end - pos)
                {
                    return false;
                }
                body.insert(body.end(), data.begin() + pos, data.begin() + pos + chunkLength);
                pos += chunkLength;
                if (!moreChunks)
                {
                    break;
                }
                if (pos >= end)
                {
                    return false;
                }
                std::size_t headerSize = 0;
                bool nextPartial = false;
                if (!decodeNewFormatBodyLength(&data[pos], end - pos, headerSize, chunkLength, nextPartial))
                {
                    return false;
                }
                pos += headerSize;
                moreChunks = nextPartial;
            }

            out.push_back(static_cast<unsigned char>(0xC0 | tag));
            appendNewFormatLength(out, body.size());
            appendAll(out, body);
            rewroteAny = true;
        }
        return rewroteAny;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Whole-buffer convenience form of reassemblePartialBodyLengthRange above.
bool reassemblePartialBodyLengths(const std::vector<unsigned char>& data, std::vector<unsigned char>& out)
{
    try
    {
        return reassemblePartialBodyLengthRange(data, 0, data.size(), out);
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

// ================================================================================================
// RFC 4880bis / crypto-refresh EdDSA Legacy (algorithm 22, Ed25519) and ECDH (algorithm 18, here
// only used with Curve25519/X25519) public key packet bodies -- byte layout confirmed by
// generating a real Ed25519+Cv25519 identity with a local GnuPG 2.5.21 install and inspecting its
// exported packets directly (gpg --list-packets / hex dump), not from the spec text alone,
// since GnuPG is this engine's actual interop target. Both curve OIDs below are DER content
// octets only (no universal tag 0x06, no separate outer length -- the packet format's own 1-byte
// "OID length" field IS the length prefix): Ed25519 = 1.3.6.1.4.1.11591.15.1 (9 octets), Curve25519
// = 1.3.6.1.4.1.3029.1.5.1 (10 octets). The EC point itself is stored "native" -- CryptoPP's
// ed25519/x25519 raw 32-byte byte arrays copied verbatim, no endianness conversion -- prefixed
// with 0x40 and then MPI-encoded by treating the resulting 33-byte blob as one big-endian integer
// for bit-counting purposes only (this is the same quirk real implementations use: the blob is
// semantically a little-endian-encoded point, but the MPI wrapper around it is computed as if it
// were plain big-endian bytes). Secret scalars (in buildEd25519SecretKeyCleartext/
// buildX25519SecretKeyCleartext below) use the same native-bytes-as-MPI convention but WITHOUT the
// 0x40 prefix (only public POINTS get that prefix, per RFC 4880bis 5.6.5/5.6.6).
// ================================================================================================

const unsigned char PGP_ED25519_OID[9] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };
const unsigned char PGP_X25519_OID[10] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
const unsigned char PGP_ALGO_RSA      = 1;
const unsigned char PGP_ALGO_EDDSA    = 22;
const unsigned char PGP_ALGO_ECDH     = 18;

std::vector<unsigned char> encodeNativePointMpi(const unsigned char point[32])
{
    unsigned char blob[33];
    blob[0] = 0x40;
    std::memcpy(blob + 1, point, 32);
    const CryptoPP::Integer blobInt(blob, 33);
    return encodeMpi(blobInt);
}
// -----------------------------------------------------------------------------

bool readNativePointMpi(const std::vector<unsigned char>& body, std::size_t& pos, unsigned char pointOut[32])
{
    try
    {
        if (pos + 2 > body.size())
        {
            return false;
        }
        const std::size_t bitLength = readBigEndian16(body, pos);
        pos += 2;
        const std::size_t byteLength = (bitLength + 7) / 8;
        if (byteLength != 33 || pos + byteLength > body.size() || body[pos] != 0x40)
        {
            return false;
        }
        std::memcpy(pointOut, &body[pos + 1], 32);
        pos += byteLength;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> buildEd25519PublicKeyPacketBody(const std::uint32_t creationTime, const unsigned char publicKey[32])
{
    std::vector<unsigned char> body;
    body.push_back(4);
    appendBigEndian32(body, creationTime);
    body.push_back(PGP_ALGO_EDDSA);
    body.push_back(static_cast<unsigned char>(sizeof(PGP_ED25519_OID)));
    appendAll(body, std::vector<unsigned char>(PGP_ED25519_OID, PGP_ED25519_OID + sizeof(PGP_ED25519_OID)));
    appendAll(body, encodeNativePointMpi(publicKey));
    return body;
}
// -----------------------------------------------------------------------------

// KDF parameters (RFC 6637 section 8): 1-octet size of the following fields, then reserved(1)=1,
// KDF hash algorithm, and the symmetric key-wrap algorithm -- SHA-256 (8) / AES-128 (7) below match
// real GnuPG's own default pairing for Curve25519 (confirmed by inspecting a real exported cv25519
// subkey), so computeEcdhKek/aesKeyWrap below hardcode the same pairing rather than negotiating.
std::vector<unsigned char> buildX25519PublicKeyPacketBody(const std::uint32_t creationTime, const unsigned char publicKey[32])
{
    std::vector<unsigned char> body;
    body.push_back(4);
    appendBigEndian32(body, creationTime);
    body.push_back(PGP_ALGO_ECDH);
    body.push_back(static_cast<unsigned char>(sizeof(PGP_X25519_OID)));
    appendAll(body, std::vector<unsigned char>(PGP_X25519_OID, PGP_X25519_OID + sizeof(PGP_X25519_OID)));
    appendAll(body, encodeNativePointMpi(publicKey));
    body.push_back(3);
    body.push_back(1);
    body.push_back(8);
    body.push_back(7);
    return body;
}
// -----------------------------------------------------------------------------

bool parseEd25519PublicKeyPacketBody(const std::vector<unsigned char>& body, unsigned char publicKeyOut[32], unsigned char keyIdOut[8])
{
    try
    {
        if (body.size() < 7 || body[0] != 4 || body[5] != PGP_ALGO_EDDSA)
        {
            return false;
        }
        if (body[6] != sizeof(PGP_ED25519_OID) || body.size() < 7 + sizeof(PGP_ED25519_OID) ||
            std::memcmp(&body[7], PGP_ED25519_OID, sizeof(PGP_ED25519_OID)) != 0)
        {
            return false;
        }
        std::size_t pos = 7 + sizeof(PGP_ED25519_OID);
        if (!readNativePointMpi(body, pos, publicKeyOut))
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

bool parseX25519PublicKeyPacketBody(const std::vector<unsigned char>& body, unsigned char publicKeyOut[32], unsigned char keyIdOut[8], unsigned char fingerprintOut[20])
{
    try
    {
        if (body.size() < 7 || body[0] != 4 || body[5] != PGP_ALGO_ECDH)
        {
            return false;
        }
        if (body[6] != sizeof(PGP_X25519_OID) || body.size() < 7 + sizeof(PGP_X25519_OID) ||
            std::memcmp(&body[7], PGP_X25519_OID, sizeof(PGP_X25519_OID)) != 0)
        {
            return false;
        }
        std::size_t pos = 7 + sizeof(PGP_X25519_OID);
        if (!readNativePointMpi(body, pos, publicKeyOut))
        {
            return false;
        }
        // KDF params field (length-prefixed, 4 bytes total for the SHA-256/AES-128 pairing this
        // engine always writes/expects) intentionally not validated here -- see this section's own
        // top comment: this engine hardcodes SHA-256/AES-128 for every X25519 peer regardless of
        // what its own KDF params advertise, matching the overwhelming real-world convention.
        computeFingerprintAndKeyId(body, fingerprintOut, keyIdOut);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> buildEd25519SecretKeyCleartext(const unsigned char privateKey[32])
{
    const CryptoPP::Integer scalarInt(privateKey, 32);
    return encodeMpi(scalarInt);
}
// -----------------------------------------------------------------------------

std::vector<unsigned char> buildX25519SecretKeyCleartext(const unsigned char privateKey[32])
{
    const CryptoPP::Integer scalarInt(privateKey, 32);
    return encodeMpi(scalarInt);
}
// -----------------------------------------------------------------------------

// ================================================================================================
// RFC 3394 AES Key Wrap -- used only by the ECDH (X25519) PKESK path to wrap the AES session key
// under the ECDH-derived KEK (RFC 6637 section 8). This CryptoPP version (8.9) ships no ready-made
// key-wrap primitive, so it is hand-implemented directly against the RFC's own pseudocode using
// CryptoPP::AES's raw single-block interface.
// ================================================================================================

std::vector<unsigned char> aesKeyWrap(const unsigned char* kek, const std::size_t kekLength, const std::vector<unsigned char>& plaintext)
{
    try
    {
        if (plaintext.empty() || plaintext.size() % 8 != 0)
        {
            return std::vector<unsigned char>();
        }
        const std::size_t n = plaintext.size() / 8;

        CryptoPP::AES::Encryption aes;
        aes.SetKey(kek, kekLength);

        unsigned char a[8] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
        std::vector<unsigned char> r(plaintext);

        for (unsigned int j = 0; j <= 5; ++j)
        {
            for (std::size_t i = 1; i <= n; ++i)
            {
                unsigned char block[16];
                std::memcpy(block, a, 8);
                std::memcpy(block + 8, &r[(i - 1) * 8], 8);
                unsigned char encrypted[16];
                aes.ProcessBlock(block, encrypted);
                std::memcpy(a, encrypted, 8);
                const std::uint64_t t = static_cast<std::uint64_t>(n) * static_cast<std::uint64_t>(j) + static_cast<std::uint64_t>(i);
                for (int b = 0; b < 8; ++b)
                {
                    a[7 - b] = static_cast<unsigned char>(a[7 - b] ^ static_cast<unsigned char>((t >> (8 * b)) & 0xFF));
                }
                std::memcpy(&r[(i - 1) * 8], encrypted + 8, 8);
            }
        }

        std::vector<unsigned char> out(8 + plaintext.size());
        std::memcpy(&out[0], a, 8);
        std::memcpy(&out[8], r.data(), r.size());
        return out;
    }
    catch (...)
    {
        return std::vector<unsigned char>();
    }
}
// -----------------------------------------------------------------------------

bool aesKeyUnwrap(const unsigned char* kek, const std::size_t kekLength, const std::vector<unsigned char>& ciphertext, std::vector<unsigned char>& outPlaintext)
{
    try
    {
        if (ciphertext.size() < 16 || ciphertext.size() % 8 != 0)
        {
            return false;
        }
        const std::size_t n = (ciphertext.size() / 8) - 1;

        CryptoPP::AES::Decryption aes;
        aes.SetKey(kek, kekLength);

        unsigned char a[8];
        std::memcpy(a, &ciphertext[0], 8);
        std::vector<unsigned char> r(ciphertext.begin() + 8, ciphertext.end());

        for (int j = 5; j >= 0; --j)
        {
            for (std::size_t i = n; i >= 1; --i)
            {
                const std::uint64_t t = static_cast<std::uint64_t>(n) * static_cast<std::uint64_t>(j) + static_cast<std::uint64_t>(i);
                unsigned char aXor[8];
                std::memcpy(aXor, a, 8);
                for (int b = 0; b < 8; ++b)
                {
                    aXor[7 - b] = static_cast<unsigned char>(aXor[7 - b] ^ static_cast<unsigned char>((t >> (8 * b)) & 0xFF));
                }
                unsigned char block[16];
                std::memcpy(block, aXor, 8);
                std::memcpy(block + 8, &r[(i - 1) * 8], 8);
                unsigned char decrypted[16];
                aes.ProcessBlock(block, decrypted);
                std::memcpy(a, decrypted, 8);
                std::memcpy(&r[(i - 1) * 8], decrypted + 8, 8);
            }
        }

        static const unsigned char expectedIv[8] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
        if (std::memcmp(a, expectedIv, 8) != 0)
        {
            return false;
        }
        outPlaintext = r;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// RFC 6637 section 7 KDF: Z = leading kekLength octets of HASH(00000001 || sharedSecret || param).
// sharedSecret is the raw, native-byte-order X25519 shared secret (RFC 7748 output, exactly as
// CryptoPP::x25519::Agree produces it) -- Curve25519 is a documented special case in the crypto-
// refresh draft where this raw fixed-size octet string is used directly as the KDF's "X(S)" input,
// unlike classical Weierstrass curves (P-256 etc.) where X(S) is instead the shared point's
// x-coordinate MPI-stripped of its length prefix. Verified empirically below via a real round-trip
// against GnuPG (see RunPgpGnuPgX25519InteropTest), not from spec text alone.
std::vector<unsigned char> computeEcdhKek(const unsigned char sharedSecret[32], const std::vector<unsigned char>& param, const std::size_t kekLength)
{
    try
    {
        std::vector<unsigned char> hashInput;
        appendBigEndian32(hashInput, 1);
        hashInput.insert(hashInput.end(), sharedSecret, sharedSecret + 32);
        appendAll(hashInput, param);
        unsigned char digest[32];
        CryptoPP::SHA256().CalculateDigest(digest, hashInput.data(), hashInput.size());
        return std::vector<unsigned char>(digest, digest + kekLength);
    }
    catch (...)
    {
        return std::vector<unsigned char>();
    }
}
// -----------------------------------------------------------------------------

// RFC 6637 section 7 "param": curve OID (length-prefixed) || public key algorithm ID (18) || the
// same 4-byte KDF-params field written into the key (03 01 08 07, see buildX25519PublicKeyPacketBody)
// || the fixed 20-octet ASCII string "Anonymous Sender    " || the recipient encryption subkey's
// own 20-byte v4 fingerprint.
std::vector<unsigned char> buildEcdhKdfParam(const unsigned char recipientSubkeyFingerprint[20])
{
    std::vector<unsigned char> param;
    param.push_back(static_cast<unsigned char>(sizeof(PGP_X25519_OID)));
    appendAll(param, std::vector<unsigned char>(PGP_X25519_OID, PGP_X25519_OID + sizeof(PGP_X25519_OID)));
    param.push_back(PGP_ALGO_ECDH);
    param.push_back(3);
    param.push_back(1);
    param.push_back(8);
    param.push_back(7);
    static const unsigned char anonymousSender[20] =
    {
        'A', 'n', 'o', 'n', 'y', 'm', 'o', 'u', 's', ' ', 'S', 'e', 'n', 'd', 'e', 'r', ' ', ' ', ' ', ' '
    };
    param.insert(param.end(), anonymousSender, anonymousSender + 20);
    param.insert(param.end(), recipientSubkeyFingerprint, recipientSubkeyFingerprint + 20);
    return param;
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

// RFC 4880 section 5.2.3.6 (type 9): number of seconds after the signed key's own creation time
// that it expires. Only meaningful appended to a self-certification (0x13, primary key
// expiration) or subkey-binding (0x18, subkey expiration) signature's hashed subpackets --
// omitted entirely (not this subpacket with value 0) means "never expires" by RFC 4880
// convention, so callers should simply not append this when expirationSeconds is 0.
std::vector<unsigned char> buildKeyExpirationSubpacket(const std::uint32_t expirationSeconds)
{
    std::vector<unsigned char> sub;
    std::vector<unsigned char> body;
    appendBigEndian32(body, expirationSeconds);
    appendSubpacket(sub, 9, body);
    return sub;
}
// -----------------------------------------------------------------------------

// RFC 4880 section 5.2.3.23 (type 29): 1-byte machine-readable reason code followed by an
// optional UTF-8 human-readable reason. Appended to a revocation signature's (0x20/0x28) hashed
// subpackets by RevokeKeyArmored.
std::vector<unsigned char> buildRevocationReasonSubpacket(const unsigned char reasonCode, const char* reasonText, const int reasonTextSize)
{
    std::vector<unsigned char> sub;
    std::vector<unsigned char> body;
    body.push_back(reasonCode);
    if (reasonText != nullptr && reasonTextSize > 0)
    {
        body.insert(body.end(), reasonText, reasonText + reasonTextSize);
    }
    appendSubpacket(sub, 29, body);
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

std::vector<unsigned char> buildRsaSecretKeyCleartext(const CryptoPP::RSA::PrivateKey& privateKey)
{
    std::vector<unsigned char> cleartext;
    appendAll(cleartext, encodeMpi(privateKey.GetPrivateExponent()));
    appendAll(cleartext, encodeMpi(privateKey.GetPrime1()));
    appendAll(cleartext, encodeMpi(privateKey.GetPrime2()));
    appendAll(cleartext, encodeMpi(privateKey.GetMultiplicativeInverseOfPrime2ModPrime1()));
    return cleartext;
}
// -----------------------------------------------------------------------------

// Iterated+Salted, SHA-1-checksummed (usage octet 254) secret-key protection envelope (RFC 4880
// 5.5.3) -- algorithm-agnostic: cleartext is the already-built concatenation of the secret key's
// own MPI(s) (RSA's 4 MPIs d/p/q/u, or a single raw-scalar MPI for Ed25519/X25519, see
// buildRsaSecretKeyCleartext/buildEd25519SecretKeyCleartext/buildX25519SecretKeyCleartext above).
std::vector<unsigned char> encryptSecretKeyMaterial(const std::vector<unsigned char>& publicKeyPacketBody, const std::vector<unsigned char>& cleartext, const char* password, const int passwordSize)
{
    try
    {
        CryptoPP::AutoSeededRandomPool rng;

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

// pkAlgorithm/hashAlgorithm are no longer hardcoded to RSA/SHA-256 here -- this parser accepts
// both this engine's two supported combinations (RSA+SHA-256, algorithm octet 1/hash octet 8; or
// EdDSA+SHA-512, algorithm octet 22/hash octet 10, matching real GnuPG's own Ed25519 signatures)
// and leaves the algorithm-specific interpretation of the trailing MPI(s) to the caller:
// signatureMpiValue is RSA's single signature-integer MPI OR EdDSA's "r" MPI; signatureMpiValue2
// is only populated (and only meaningful) for EdDSA, holding its second "s" MPI.
struct ParsedSignature
{
    bool valid;
    unsigned char pkAlgorithm;
    unsigned char signatureType;
    unsigned char hashAlgorithm;
    std::vector<unsigned char> hashedSubpackets;
    std::vector<unsigned char> signatureMpiValue;
    std::vector<unsigned char> signatureMpiValue2;

    ParsedSignature() : valid(false), pkAlgorithm(0), signatureType(0), hashAlgorithm(0) {}
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
        result.pkAlgorithm = body[pos]; pos += 1;
        if (result.pkAlgorithm != PGP_ALGO_RSA && result.pkAlgorithm != PGP_ALGO_EDDSA)
        {
            return result;
        }
        result.hashAlgorithm = body[pos]; pos += 1;
        if (result.hashAlgorithm != 8 && result.hashAlgorithm != 10)
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
        pos += sigByteLength;

        if (result.pkAlgorithm == PGP_ALGO_EDDSA)
        {
            if (pos + 2 > body.size())
            {
                return result;
            }
            const std::size_t sigBitLength2 = readBigEndian16(body, pos);
            pos += 2;
            const std::size_t sigByteLength2 = (sigBitLength2 + 7) / 8;
            if (pos + sigByteLength2 > body.size())
            {
                return result;
            }
            result.signatureMpiValue2.assign(body.begin() + pos, body.begin() + pos + sigByteLength2);
        }

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
        if (!parsed.valid || parsed.pkAlgorithm != PGP_ALGO_RSA || parsed.hashAlgorithm != 8)
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
// Ed25519 (EdDSA Legacy, algorithm 22) signature packets -- same v4 signature framing as
// buildSignaturePacket/verifySignaturePacket above, but SHA-512 (hash octet 10, per crypto-refresh's
// mandatory EdDSA/SHA-512 pairing and confirmed against a real GnuPG-produced Ed25519 self-
// signature) instead of SHA-256, and two MPIs (r, s -- CryptoPP's ed25519 64-byte raw r||s
// signature output, split in half, each half copied verbatim into a big-endian MPI with no
// endianness conversion, same native-bytes-as-MPI convention as the public key point) instead of
// RSA's single signature-integer MPI.
// ================================================================================================

std::vector<unsigned char> buildEd25519SignaturePacket(const unsigned char privateKey[32], const unsigned char signatureType, const std::vector<unsigned char>& documentData, const std::vector<unsigned char>& extraHashedSubpacket, const unsigned char issuerKeyId[8])
{
    try
    {
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
        toBeHashed.push_back(PGP_ALGO_EDDSA);
        toBeHashed.push_back(10);
        appendBigEndian16(toBeHashed, static_cast<std::uint16_t>(hashedSubpackets.size()));
        appendAll(toBeHashed, hashedSubpackets);

        const std::size_t hashedPortionLength = 6 + hashedSubpackets.size();
        toBeHashed.push_back(4);
        toBeHashed.push_back(0xFF);
        appendBigEndian32(toBeHashed, static_cast<std::uint32_t>(hashedPortionLength));

        // OpenPGP's v4 EdDSA convention (confirmed empirically against a real GnuPG-produced
        // self-signature -- see this file's own commit history/notes) is NOT RFC 8032 PureEdDSA
        // over the raw trailer bytes: it hashes the trailer with the declared hash algorithm
        // (SHA-512 here) FIRST, then runs the Ed25519 core signing primitive over that 64-byte
        // digest as if it were an ordinary fixed-size message -- i.e. the same "hash algorithm
        // octet selects what actually gets hashed, then the PK primitive signs the digest"
        // pattern RSA/DSA/ECDSA use, just reusing Ed25519's own signing procedure as the raw PK
        // primitive rather than a padding scheme. A naive RFC 8032 PureEdDSA call directly over
        // toBeHashed (letting Ed25519 do its own internal hashing) produces a signature real
        // GnuPG rejects as "bad signature" even though it verifies fine against this engine's own
        // (self-consistently wrong) verifier -- this was caught only by real-GnuPG interop
        // testing, not by this engine's own round-trip tests.
        unsigned char leftHash[64];
        CryptoPP::SHA512().CalculateDigest(leftHash, toBeHashed.data(), toBeHashed.size());

        CryptoPP::ed25519Signer signer(privateKey);
        unsigned char rawSignature[64];
        signer.SignMessage(CryptoPP::NullRNG(), leftHash, 64, rawSignature);

        const CryptoPP::Integer rInt(rawSignature, 32);
        const CryptoPP::Integer sInt(rawSignature + 32, 32);

        std::vector<unsigned char> body;
        body.push_back(4);
        body.push_back(signatureType);
        body.push_back(PGP_ALGO_EDDSA);
        body.push_back(10);
        appendBigEndian16(body, static_cast<std::uint16_t>(hashedSubpackets.size()));
        appendAll(body, hashedSubpackets);
        appendBigEndian16(body, static_cast<std::uint16_t>(unhashedSubpackets.size()));
        appendAll(body, unhashedSubpackets);
        body.push_back(leftHash[0]);
        body.push_back(leftHash[1]);
        appendAll(body, encodeMpi(rInt));
        appendAll(body, encodeMpi(sInt));

        return writePacket(PGP_TAG_SIGNATURE, body);
    }
    catch (...)
    {
        return std::vector<unsigned char>();
    }
}
// -----------------------------------------------------------------------------

// Same NO_ERROR/*isValid convention as verifySignaturePacket above.
bool verifyEd25519SignaturePacket(const unsigned char publicKey[32], const std::vector<unsigned char>& documentData, const std::vector<unsigned char>& signaturePacketBytes, bool* isValid)
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
        if (!parsed.valid || parsed.pkAlgorithm != PGP_ALGO_EDDSA || parsed.hashAlgorithm != 10)
        {
            return false;
        }

        std::vector<unsigned char> toBeHashed;
        appendAll(toBeHashed, documentData);
        toBeHashed.push_back(4);
        toBeHashed.push_back(parsed.signatureType);
        toBeHashed.push_back(PGP_ALGO_EDDSA);
        toBeHashed.push_back(10);
        appendBigEndian16(toBeHashed, static_cast<std::uint16_t>(parsed.hashedSubpackets.size()));
        appendAll(toBeHashed, parsed.hashedSubpackets);

        const std::size_t hashedPortionLength = 6 + parsed.hashedSubpackets.size();
        toBeHashed.push_back(4);
        toBeHashed.push_back(0xFF);
        appendBigEndian32(toBeHashed, static_cast<std::uint32_t>(hashedPortionLength));

        unsigned char rawSignature[64];
        std::memset(rawSignature, 0, 64);
        const CryptoPP::Integer rInt(parsed.signatureMpiValue.data(), parsed.signatureMpiValue.size());
        const CryptoPP::Integer sInt(parsed.signatureMpiValue2.data(), parsed.signatureMpiValue2.size());
        rInt.Encode(rawSignature, 32);
        sInt.Encode(rawSignature + 32, 32);

        // See buildEd25519SignaturePacket's own comment -- OpenPGP EdDSA verifies the SHA-512
        // digest of toBeHashed through Ed25519's core primitive, not toBeHashed itself.
        unsigned char digest[64];
        CryptoPP::SHA512().CalculateDigest(digest, toBeHashed.data(), toBeHashed.size());

        CryptoPP::ed25519Verifier verifier(publicKey);
        *isValid = verifier.VerifyMessage(digest, 64, rawSignature, 64);
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

// Builds a single PKESK packet (header+body) for one recipient, RSA-PKCS#1v1.5 or ECDH per
// recipient.algorithm -- shared by buildEncryptedMessageMultiRecipient below and
// encryptFileStreaming further down.
std::vector<unsigned char> buildPkeskPacketForRecipient(const PgpEncryptionRecipient& recipient, const unsigned char* sessionKey, const std::size_t sessionKeyLength)
{
    try
    {
        CryptoPP::AutoSeededRandomPool rng;

        std::vector<unsigned char> sessionKeyPlain;
        sessionKeyPlain.push_back(9); // AES-256 -- this engine always generates a 32-byte session key.
        sessionKeyPlain.insert(sessionKeyPlain.end(), sessionKey, sessionKey + sessionKeyLength);
        {
            unsigned int checksum = 0;
            for (std::size_t i = 0; i < sessionKeyLength; ++i)
            {
                checksum += sessionKey[i];
            }
            sessionKeyPlain.push_back(static_cast<unsigned char>((checksum >> 8) & 0xFF));
            sessionKeyPlain.push_back(static_cast<unsigned char>(checksum & 0xFF));
        }

        if (recipient.algorithm == PGP_KEY_ALGORITHM_RSA)
        {
            CryptoPP::RSAES<CryptoPP::PKCS1v15>::Encryptor encryptor(recipient.rsaPublicKey);
            std::vector<unsigned char> pkcsCipher(encryptor.FixedCiphertextLength());
            encryptor.Encrypt(rng, sessionKeyPlain.data(), sessionKeyPlain.size(), pkcsCipher.data());
            const CryptoPP::Integer cipherInt(pkcsCipher.data(), pkcsCipher.size());
            const std::vector<unsigned char> cipherMpi = encodeMpi(cipherInt);

            std::vector<unsigned char> pkeskBody;
            pkeskBody.push_back(3);
            pkeskBody.insert(pkeskBody.end(), recipient.rsaKeyId, recipient.rsaKeyId + 8);
            pkeskBody.push_back(PGP_ALGO_RSA);
            appendAll(pkeskBody, cipherMpi);
            return writePacket(PGP_TAG_PKESK, pkeskBody);
        }
        else
        {
            CryptoPP::x25519 dh;
            unsigned char ephemeralPrivateKey[32];
            unsigned char ephemeralPublicKey[32];
            dh.GeneratePrivateKey(rng, ephemeralPrivateKey);
            dh.GeneratePublicKey(rng, ephemeralPrivateKey, ephemeralPublicKey);

            unsigned char sharedSecret[32];
            if (!dh.Agree(sharedSecret, ephemeralPrivateKey, recipient.x25519PublicKey))
            {
                return std::vector<unsigned char>();
            }

            const std::vector<unsigned char> param = buildEcdhKdfParam(recipient.x25519Fingerprint);
            const std::vector<unsigned char> kek = computeEcdhKek(sharedSecret, param, 16);
            if (kek.size() != 16)
            {
                return std::vector<unsigned char>();
            }

            // RFC 6637 section 8: PKCS#5-pad sessionKeyPlain to a multiple of 8 octets before
            // AES key-wrapping it (a value already a multiple of 8 still gets one full extra
            // block of padding -- the value at every padding byte position IS the padding length).
            std::vector<unsigned char> padded = sessionKeyPlain;
            const std::size_t padLength = 8 - (padded.size() % 8);
            for (std::size_t i = 0; i < padLength; ++i)
            {
                padded.push_back(static_cast<unsigned char>(padLength));
            }
            const std::vector<unsigned char> wrapped = aesKeyWrap(kek.data(), kek.size(), padded);
            if (wrapped.empty())
            {
                return std::vector<unsigned char>();
            }

            std::vector<unsigned char> pkeskBody;
            pkeskBody.push_back(3);
            pkeskBody.insert(pkeskBody.end(), recipient.x25519KeyId, recipient.x25519KeyId + 8);
            pkeskBody.push_back(PGP_ALGO_ECDH);
            appendAll(pkeskBody, encodeNativePointMpi(ephemeralPublicKey));
            pkeskBody.push_back(static_cast<unsigned char>(wrapped.size()));
            appendAll(pkeskBody, wrapped);
            return writePacket(PGP_TAG_PKESK, pkeskBody);
        }
    }
    catch (...)
    {
        return std::vector<unsigned char>();
    }
}
// -----------------------------------------------------------------------------

// One PKESK packet per entry in `recipients` (all wrapping the SAME randomly generated session
// key), followed by one shared SEIP packet -- the multi-recipient extension of what used to be
// buildEncryptedMessage(single RSA recipient); recipients.size()==1 with a single RSA entry
// reproduces that exact original single-recipient wire format byte-for-byte.
bool buildEncryptedMessageMultiRecipient(const std::vector<PgpEncryptionRecipient>& recipients, const unsigned char* plaintext, const std::size_t plaintextSize, std::vector<unsigned char>& out)
{
    try
    {
        if (recipients.empty())
        {
            return false;
        }
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

        out.clear();
        for (std::size_t i = 0; i < recipients.size(); ++i)
        {
            const std::vector<unsigned char> pkeskPacket = buildPkeskPacketForRecipient(recipients[i], sessionKey, 32);
            if (pkeskPacket.empty())
            {
                return false;
            }
            appendAll(out, pkeskPacket);
        }
        appendAll(out, seipPacket);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Scans one or more leading PKESK (tag 1) packets in `message`, looking for the one addressed to
// THIS recipient's own Key ID (ownAlgorithm/ownRsaSubkey/ownX25519PrivateKey/ownSubkeyKeyId --
// only the fields matching ownAlgorithm are used), decrypts that one PKESK's session key, and
// keeps scanning to the start of the following SEIP packet regardless of which one matched -- a
// real multi-recipient message may carry PKESKs for OTHER recipients before or after ours, all of
// which must be skipped, not just the first.
bool parseAndDecryptMessage(const PgpKeyAlgorithm ownAlgorithm, const CryptoPP::RSA::PrivateKey& ownRsaSubkey, const unsigned char ownX25519PrivateKey[32], const unsigned char ownSubkeyFingerprint[20], const unsigned char ownSubkeyKeyId[8], const std::vector<unsigned char>& inputMessage, std::vector<unsigned char>& outPlaintext)
{
    try
    {
        // Real GnuPG wraps the SEIP packet in new-format partial-body-length framing (RFC 4880
        // section 4.2.2.4) as soon as the message is larger than its own output buffer -- verified
        // against GnuPG 2.5.21, which does it both for piped input and for an ordinary input file
        // of a few hundred KB. Splice any such packet back into one contiguous body up front so
        // every step below still sees the single-definite-length packet layout it was written for;
        // when there is nothing to splice (every message this engine itself produces, and every
        // small GnuPG message) this is a no-op and the original buffer is used unchanged.
        std::vector<unsigned char> reassembledMessage;
        const bool messageReassembled = reassemblePartialBodyLengths(inputMessage, reassembledMessage);
        const std::vector<unsigned char>& message = messageReassembled ? reassembledMessage : inputMessage;

        std::size_t pos = 0;
        std::vector<unsigned char> sessionPlain;
        bool found = false;

        while (true)
        {
            std::size_t peekPos = pos;
            unsigned char tag = 0;
            std::size_t bodyLength = 0;
            if (!readPacketHeader(message, peekPos, tag, bodyLength) || tag != PGP_TAG_PKESK)
            {
                break;
            }
            const std::size_t pkeskEnd = peekPos + bodyLength;
            if (pkeskEnd > message.size())
            {
                return false;
            }

            std::size_t p = peekPos;
            if (message[p] != 3)
            {
                return false;
            }
            p += 1;
            const unsigned char* thisKeyId = &message[p];
            p += 8;
            const unsigned char pkAlgo = message[p];
            p += 1;

            const bool keyIdMatches = (std::memcmp(thisKeyId, ownSubkeyKeyId, 8) == 0);
            const bool algoMatches = (ownAlgorithm == PGP_KEY_ALGORITHM_RSA) ? (pkAlgo == PGP_ALGO_RSA) : (pkAlgo == PGP_ALGO_ECDH);

            if (!found && keyIdMatches && algoMatches)
            {
                if (pkAlgo == PGP_ALGO_RSA)
                {
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

                    const std::size_t modulusLength = rsaModulusByteLength(ownRsaSubkey.GetModulus());
                    std::vector<unsigned char> fixedCipher(modulusLength, 0);
                    cipherInt.Encode(fixedCipher.data(), modulusLength);

                    CryptoPP::RSAES<CryptoPP::PKCS1v15>::Decryptor decryptor(ownRsaSubkey);
                    std::vector<unsigned char> plain(decryptor.FixedMaxPlaintextLength());
                    CryptoPP::AutoSeededRandomPool rng;
                    const CryptoPP::DecodingResult result = decryptor.Decrypt(rng, fixedCipher.data(), fixedCipher.size(), plain.data());
                    if (result.isValidCoding)
                    {
                        plain.resize(result.messageLength);
                        sessionPlain = plain;
                        found = true;
                    }
                }
                else
                {
                    unsigned char ephemeralPublicKey[32];
                    std::size_t mpiPos = p;
                    if (readNativePointMpi(message, mpiPos, ephemeralPublicKey) && mpiPos < pkeskEnd)
                    {
                        const unsigned char wrappedLength = message[mpiPos];
                        mpiPos += 1;
                        if (mpiPos + wrappedLength <= pkeskEnd)
                        {
                            const std::vector<unsigned char> wrapped(message.begin() + mpiPos, message.begin() + mpiPos + wrappedLength);

                            CryptoPP::x25519 dh;
                            unsigned char sharedSecret[32];
                            if (dh.Agree(sharedSecret, ownX25519PrivateKey, ephemeralPublicKey))
                            {
                                const std::vector<unsigned char> param = buildEcdhKdfParam(ownSubkeyFingerprint);
                                const std::vector<unsigned char> kek = computeEcdhKek(sharedSecret, param, 16);
                                std::vector<unsigned char> unwrapped;
                                if (kek.size() == 16 && aesKeyUnwrap(kek.data(), kek.size(), wrapped, unwrapped) && !unwrapped.empty())
                                {
                                    const unsigned char padLength = unwrapped.back();
                                    if (padLength >= 1 && padLength <= 8 && static_cast<std::size_t>(padLength) <= unwrapped.size())
                                    {
                                        unwrapped.resize(unwrapped.size() - padLength);
                                        sessionPlain = unwrapped;
                                        found = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            pos = pkeskEnd;
        }

        if (!found || sessionPlain.empty())
        {
            return false;
        }
        // v1 always PRODUCES AES-256 (see buildEncryptedMessageMultiRecipient), but real-world
        // senders (verified against GnuPG 2.5.21, which defaults to AES-128 for a recipient key
        // with no advertised preference) may choose any AES family member -- accept all three to
        // decrypt their messages, not just our own.
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

        // The packet nested inside the SEIP body (a Compressed Data or Literal Data packet) may use
        // partial-body-length framing of its own, independently of the SEIP's -- GnuPG does exactly
        // that for the Literal Data packet when its own input size is unknown (piped stdin). Splice
        // that one back together too, over the body region only (18-byte CFB prefix skipped, MDC
        // trailer excluded); when nothing needs splicing the decrypted buffer is parsed in place as
        // before.
        std::vector<unsigned char> reassembledInner;
        const bool innerReassembled = reassemblePartialBodyLengthRange(plainForCfb, 18, mdcTagOffset, reassembledInner);
        const std::vector<unsigned char>& innerData = innerReassembled ? reassembledInner : plainForCfb;

        std::size_t innerPos = innerReassembled ? 0 : 18;
        const std::size_t innerEnd = innerReassembled ? reassembledInner.size() : mdcTagOffset;
        unsigned char innerTag = 0;
        std::size_t innerLength = 0;
        if (!readPacketHeader(innerData, innerPos, innerTag, innerLength, innerEnd) || innerPos + innerLength > innerEnd)
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
            const unsigned char compAlgo = innerData[innerPos];
            const unsigned char* compData = &innerData[innerPos + 1];
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

            // The Literal Data packet that comes back out of the decompressor carries its own
            // framing, which GnuPG also splits into partial-body-length chunks when it streamed the
            // plaintext in from a source of unknown size -- splice it back together the same way.
            std::vector<unsigned char> reassembledLiteralPacket;
            if (reassemblePartialBodyLengths(decompressedPacket, reassembledLiteralPacket))
            {
                decompressedPacket.swap(reassembledLiteralPacket);
            }

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
            literalBody = &innerData[innerPos];
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

int encryptFileStreaming(const std::vector<PgpEncryptionRecipient>& recipients, HANDLE inputFileHandle, const unsigned long long fileSize, HANDLE outputFileHandle, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (recipients.empty())
        {
            return INVALID_ARGUMENT;
        }
        CryptoPP::AutoSeededRandomPool rng;

        unsigned char sessionKey[32];
        rng.GenerateBlock(sessionKey, 32);
        for (std::size_t r = 0; r < recipients.size(); ++r)
        {
            const std::vector<unsigned char> pkeskPacket = buildPkeskPacketForRecipient(recipients[r], sessionKey, 32);
            if (pkeskPacket.empty())
            {
                return UNEXPECTED_ERROR;
            }
            if (!writeFileExact(outputFileHandle, pkeskPacket.data(), static_cast<DWORD>(pkeskPacket.size())))
            {
                return FILE_IO_ERROR;
            }
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

// Streams inputFileHandle's plaintext, wrapped as a Literal Data packet (tag 11, header+prefix
// built upfront exactly like encryptFileStreaming's own literalHeader/literalPrefix -- fileSize is
// known, so this part's length is still exactly known even though the compressed size that follows
// is not), into compressionAlgorithmOctet's Deflator (ZIP, octet 1) or ZlibCompressor (ZLIB, octet
// 2), draining compressed bytes out to tempFilePath as they are produced so peak memory never
// holds more than one chunk plus Crypto++'s own small internal deflate buffer. Once fully drained,
// reopens the temp file just to read back its exact size (outCompressedSize) -- the whole reason
// this two-pass split exists, see EncryptFileCompressed's own .h comment. Always creates
// tempFilePath (even on failure) so the caller can unconditionally attempt cleanup.
int compressLiteralToTempFile(HANDLE inputFileHandle, const unsigned long long fileSize, const unsigned char compressionAlgorithmOctet, const std::wstring& tempFilePath, ProgressCallback onProgress, void* progressUserData, unsigned long long& outCompressedSize)
{
    try
    {
        const HANDLE rawTempHandle = CreateFileW(tempFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawTempHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> tempHandle(rawTempHandle, &CloseHandle);

        std::vector<unsigned char> literalHeader;
        literalHeader.push_back(static_cast<unsigned char>(0xC0 | PGP_TAG_LITERAL_DATA));
        appendNewFormatLength(literalHeader, 6 + static_cast<std::size_t>(fileSize));

        std::vector<unsigned char> literalPrefix;
        literalPrefix.push_back('b');
        literalPrefix.push_back(0);
        appendBigEndian32(literalPrefix, 0);

        CryptoPP::ByteQueue* compressedQueue = new CryptoPP::ByteQueue();
        std::unique_ptr<CryptoPP::BufferedTransformation> compressor;
        if (compressionAlgorithmOctet == 2)
        {
            compressor.reset(new CryptoPP::ZlibCompressor(compressedQueue));
        }
        else
        {
            compressor.reset(new CryptoPP::Deflator(compressedQueue));
        }

        auto drainToTemp = [&]() -> bool
        {
            const std::size_t available = static_cast<std::size_t>(compressedQueue->MaxRetrievable());
            if (available == 0)
            {
                return true;
            }
            std::vector<unsigned char> drainBuf(available);
            compressedQueue->Get(drainBuf.data(), available);
            return writeFileExact(rawTempHandle, drainBuf.data(), static_cast<DWORD>(drainBuf.size()));
        };

        try
        {
            compressor->Put(literalHeader.data(), literalHeader.size());
            compressor->Put(literalPrefix.data(), literalPrefix.size());
        }
        catch (const CryptoPP::Exception&)
        {
            return UNEXPECTED_ERROR;
        }
        if (!drainToTemp())
        {
            return FILE_IO_ERROR;
        }

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
            try
            {
                compressor->Put(chunk.data(), bytesRead);
            }
            catch (const CryptoPP::Exception&)
            {
                return UNEXPECTED_ERROR;
            }
            if (!drainToTemp())
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

        try
        {
            compressor->MessageEnd();
        }
        catch (const CryptoPP::Exception&)
        {
            return UNEXPECTED_ERROR;
        }
        if (!drainToTemp())
        {
            return FILE_IO_ERROR;
        }

        tempHandle.reset(); // close so every buffered byte is flushed before the size query below.

        const HANDLE rawSizeHandle = CreateFileW(tempFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawSizeHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        LARGE_INTEGER tempSize;
        tempSize.QuadPart = 0;
        const bool sizeOk = GetFileSizeEx(rawSizeHandle, &tempSize) != 0 && tempSize.QuadPart >= 0;
        CloseHandle(rawSizeHandle);
        if (!sizeOk)
        {
            return FILE_IO_ERROR;
        }
        outCompressedSize = static_cast<unsigned long long>(tempSize.QuadPart);
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

// The compressed counterpart of encryptFileStreaming above: identical PKESK-per-recipient and
// SEIP/MDC/CFB framing, except the SEIP body wraps a Compressed Data packet (tag 8, holding
// compressionAlgorithmOctet + the already-compressed bytes sitting in tempFilePath, compressedSize
// long -- produced by compressLiteralToTempFile above) instead of wrapping the Literal Data packet
// directly. compressedSize is exact by the time this runs, so -- exactly like encryptFileStreaming
// -- every packet length here is still fully known before a single output byte is written.
int encryptFileStreamingCompressed(const std::vector<PgpEncryptionRecipient>& recipients, const std::wstring& tempFilePath, const unsigned long long compressedSize, const unsigned char compressionAlgorithmOctet, HANDLE outputFileHandle, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (recipients.empty())
        {
            return INVALID_ARGUMENT;
        }
        CryptoPP::AutoSeededRandomPool rng;

        unsigned char sessionKey[32];
        rng.GenerateBlock(sessionKey, 32);
        for (std::size_t r = 0; r < recipients.size(); ++r)
        {
            const std::vector<unsigned char> pkeskPacket = buildPkeskPacketForRecipient(recipients[r], sessionKey, 32);
            if (pkeskPacket.empty())
            {
                return UNEXPECTED_ERROR;
            }
            if (!writeFileExact(outputFileHandle, pkeskPacket.data(), static_cast<DWORD>(pkeskPacket.size())))
            {
                return FILE_IO_ERROR;
            }
        }

        const std::size_t compressedBodyLength = 1 + static_cast<std::size_t>(compressedSize);
        std::vector<unsigned char> compressedHeader;
        compressedHeader.push_back(static_cast<unsigned char>(0xC0 | PGP_TAG_COMPRESSED_DATA));
        appendNewFormatLength(compressedHeader, compressedBodyLength);

        const std::size_t innerContentLength = compressedHeader.size() + compressedBodyLength;
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

        std::vector<unsigned char> compressedHeaderCipher(compressedHeader.size());
        mdc.Update(compressedHeader.data(), compressedHeader.size());
        cfb.ProcessData(compressedHeaderCipher.data(), compressedHeader.data(), compressedHeader.size());
        if (!writeFileExact(outputFileHandle, compressedHeaderCipher.data(), static_cast<DWORD>(compressedHeaderCipher.size())))
        {
            return FILE_IO_ERROR;
        }

        unsigned char algorithmOctetCipher = 0;
        mdc.Update(&compressionAlgorithmOctet, 1);
        cfb.ProcessData(&algorithmOctetCipher, &compressionAlgorithmOctet, 1);
        if (!writeFileExact(outputFileHandle, &algorithmOctetCipher, 1))
        {
            return FILE_IO_ERROR;
        }

        const HANDLE rawTempReadHandle = CreateFileW(tempFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawTempReadHandle == INVALID_HANDLE_VALUE)
        {
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> tempReadHandle(rawTempReadHandle, &CloseHandle);

        std::vector<unsigned char> plainChunk(PGP_FILE_CHUNK_SIZE);
        std::vector<unsigned char> cipherChunk(PGP_FILE_CHUNK_SIZE);
        unsigned long long processedBytes = 0;
        for (;;)
        {
            DWORD bytesRead = 0;
            if (!ReadFile(rawTempReadHandle, plainChunk.data(), static_cast<DWORD>(plainChunk.size()), &bytesRead, nullptr))
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
                const double percentage = compressedSize > 0 ? (static_cast<double>(processedBytes) / static_cast<double>(compressedSize)) * 100.0 : 0.0;
                if (!onProgress(processedBytes, compressedSize, percentage, progressUserData))
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

int signEd25519FileStreaming(const unsigned char privateKey[32], HANDLE inputFileHandle, const unsigned long long fileSize, const unsigned char issuerKeyId[8], ProgressCallback onProgress, void* progressUserData, std::vector<unsigned char>& outSignaturePacket)
{
    try
    {
        std::vector<unsigned char> hashedSubpackets;
        std::vector<unsigned char> timeBody;
        appendBigEndian32(timeBody, static_cast<std::uint32_t>(std::time(nullptr)));
        appendSubpacket(hashedSubpackets, 2, timeBody);
        std::vector<unsigned char> unhashedSubpackets;
        appendSubpacket(unhashedSubpackets, 16, std::vector<unsigned char>(issuerKeyId, issuerKeyId + 8));

        CryptoPP::SHA512 digest;
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
            digest.Update(chunk.data(), bytesRead);
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

        std::vector<unsigned char> suffix = { 4, 0, PGP_ALGO_EDDSA, 10 };
        appendBigEndian16(suffix, static_cast<std::uint16_t>(hashedSubpackets.size()));
        appendAll(suffix, hashedSubpackets);
        suffix.push_back(4);
        suffix.push_back(0xFF);
        appendBigEndian32(suffix, static_cast<std::uint32_t>(6 + hashedSubpackets.size()));
        digest.Update(suffix.data(), suffix.size());
        unsigned char hash[64];
        digest.Final(hash);

        CryptoPP::ed25519Signer signer(privateKey);
        unsigned char signature[64];
        signer.SignMessage(CryptoPP::NullRNG(), hash, 64, signature);
        std::vector<unsigned char> body = { 4, 0, PGP_ALGO_EDDSA, 10 };
        appendBigEndian16(body, static_cast<std::uint16_t>(hashedSubpackets.size()));
        appendAll(body, hashedSubpackets);
        appendBigEndian16(body, static_cast<std::uint16_t>(unhashedSubpackets.size()));
        appendAll(body, unhashedSubpackets);
        body.push_back(hash[0]);
        body.push_back(hash[1]);
        appendAll(body, encodeMpi(CryptoPP::Integer(signature, 32)));
        appendAll(body, encodeMpi(CryptoPP::Integer(signature + 32, 32)));
        outSignaturePacket = writePacket(PGP_TAG_SIGNATURE, body);
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int verifyEd25519FileStreaming(const unsigned char publicKey[32], HANDLE inputFileHandle, const unsigned long long fileSize, const std::vector<unsigned char>& signaturePacketBytes, bool* isValid, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        std::size_t pos = 0;
        unsigned char tag = 0;
        std::size_t bodyLength = 0;
        if (!readPacketHeader(signaturePacketBytes, pos, tag, bodyLength) || tag != PGP_TAG_SIGNATURE || pos + bodyLength != signaturePacketBytes.size())
        {
            return INVALID_DATA;
        }
        const ParsedSignature parsed = parseSignaturePacketBody(std::vector<unsigned char>(signaturePacketBytes.begin() + pos, signaturePacketBytes.end()));
        if (!parsed.valid || parsed.pkAlgorithm != PGP_ALGO_EDDSA || parsed.hashAlgorithm != 10 || parsed.signatureType != 0)
        {
            return INVALID_DATA;
        }

        CryptoPP::SHA512 digest;
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
            digest.Update(chunk.data(), bytesRead);
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

        std::vector<unsigned char> suffix = { 4, parsed.signatureType, PGP_ALGO_EDDSA, 10 };
        appendBigEndian16(suffix, static_cast<std::uint16_t>(parsed.hashedSubpackets.size()));
        appendAll(suffix, parsed.hashedSubpackets);
        suffix.push_back(4);
        suffix.push_back(0xFF);
        appendBigEndian32(suffix, static_cast<std::uint32_t>(6 + parsed.hashedSubpackets.size()));
        digest.Update(suffix.data(), suffix.size());
        unsigned char hash[64];
        digest.Final(hash);
        unsigned char rawSignature[64];
        CryptoPP::Integer(parsed.signatureMpiValue.data(), parsed.signatureMpiValue.size()).Encode(rawSignature, 32);
        CryptoPP::Integer(parsed.signatureMpiValue2.data(), parsed.signatureMpiValue2.size()).Encode(rawSignature + 32, 32);
        CryptoPP::ed25519Verifier verifier(publicKey);
        *isValid = verifier.VerifyMessage(hash, 64, rawSignature, 64);
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

    // Set when the SEIP packet uses new-format partial-body-length framing (RFC 4880 section
    // 4.2.2.4) instead of one definite length -- what real GnuPG emits for anything bigger than
    // its own output buffer. encLength above is then the TOTAL ciphertext length summed over every
    // chunk (the chunk length octets themselves excluded, and the SEIP version octet already
    // subtracted), leftoverCipher is empty and the file pointer sits on the first ciphertext byte,
    // and seipChunkRemaining/seipFinalChunk describe the chunk the file pointer is currently
    // inside so the streaming reader can keep stepping over the remaining chunk headers.
    bool seipPartial;
    std::size_t seipChunkRemaining;
    bool seipFinalChunk;

    DecryptFileHeader() : ok(false), encLength(0), seipPartial(false), seipChunkRemaining(0), seipFinalChunk(false) {}
};
// -----------------------------------------------------------------------------

// Walks the chunk sequence of a new-format partial-body-length packet (RFC 4880 section 4.2.2.4)
// whose body starts at bodyStartOffset with a first chunk of firstChunkLength octets, and sums up
// how many body octets it holds in total. Only the (1, 2 or 5 octet) chunk headers are actually
// read -- each chunk's payload is skipped with a seek -- so this costs one small read per chunk and
// no payload I/O at all. The streaming SEIP reader needs this because a partial-length packet does
// not announce its total size anywhere, yet the MDC trailer can only be split off the plaintext
// once the end of the body is known. Leaves the file pointer wherever the walk ended; the caller
// repositions it.
bool scanPartialBodyTotalLength(HANDLE inputFileHandle, const unsigned long long bodyStartOffset, const std::size_t firstChunkLength, unsigned long long& totalPayload)
{
    try
    {
        LARGE_INTEGER fileSize;
        fileSize.QuadPart = 0;
        if (!GetFileSizeEx(inputFileHandle, &fileSize) || fileSize.QuadPart < 0)
        {
            return false;
        }
        const unsigned long long endOffset = static_cast<unsigned long long>(fileSize.QuadPart);

        unsigned long long total = static_cast<unsigned long long>(firstChunkLength);
        unsigned long long offset = bodyStartOffset + firstChunkLength;
        bool moreChunks = true;
        while (moreChunks)
        {
            if (offset >= endOffset)
            {
                return false;
            }
            LARGE_INTEGER moveTo;
            moveTo.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(inputFileHandle, moveTo, nullptr, FILE_BEGIN))
            {
                return false;
            }

            unsigned char header[5] = { 0, 0, 0, 0, 0 };
            DWORD bytesRead = 0;
            if (!ReadFile(inputFileHandle, header, 5, &bytesRead, nullptr) || bytesRead == 0)
            {
                return false;
            }

            std::size_t headerSize = 0;
            std::size_t chunkLength = 0;
            bool isPartial = false;
            if (!decodeNewFormatBodyLength(header, static_cast<std::size_t>(bytesRead), headerSize, chunkLength, isPartial))
            {
                return false;
            }
            total += static_cast<unsigned long long>(chunkLength);
            offset += static_cast<unsigned long long>(headerSize) + static_cast<unsigned long long>(chunkLength);
            moreChunks = isPartial;
        }

        if (offset > endOffset)
        {
            return false;
        }
        totalPayload = total;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Reads just enough of the file (a small, bounded prefix -- PKESKs plus the SEIP header are at
// most a few KB even for several RSA-4096 recipients) to recover the session key and the SEIP
// body's exact length. Scans every leading PKESK packet for the one addressed to
// ownSubkeyKeyId (multi-recipient support -- a real multi-recipient file may carry PKESKs for
// OTHER recipients before or after ours). Any ciphertext bytes read past the SEIP header in that
// same prefix are returned in leftoverCipher so decryptSeipBodyStreaming can consume them before
// reading more from the file.
DecryptFileHeader parseEncryptedFileHeader(HANDLE inputFileHandle, const PgpKeyAlgorithm ownAlgorithm, const CryptoPP::RSA::PrivateKey& recipientPrivateKey, const unsigned char ownX25519PrivateKey[32], const unsigned char ownSubkeyFingerprint[20], const unsigned char ownSubkeyKeyId[8])
{
    DecryptFileHeader result;
    try
    {
        std::vector<unsigned char> buf(65536);
        DWORD bytesRead = 0;
        if (!ReadFile(inputFileHandle, buf.data(), static_cast<DWORD>(buf.size()), &bytesRead, nullptr))
        {
            return result;
        }
        buf.resize(bytesRead);

        std::size_t pos = 0;
        std::vector<unsigned char> sessionPlain;
        bool found = false;
        while (true)
        {
            std::size_t peekPos = pos;
            unsigned char tag = 0;
            std::size_t bodyLength = 0;
            if (!readPacketHeader(buf, peekPos, tag, bodyLength) || tag != PGP_TAG_PKESK || peekPos + bodyLength > buf.size())
            {
                break;
            }
            const std::size_t pkeskEnd = peekPos + bodyLength;

            std::size_t p = peekPos;
            if (p >= pkeskEnd || buf[p] != 3)
            {
                pos = pkeskEnd;
                continue;
            }
            p += 1;
            if (p + 9 > pkeskEnd)
            {
                pos = pkeskEnd;
                continue;
            }
            const unsigned char thisKeyId[8] = { buf[p], buf[p+1], buf[p+2], buf[p+3], buf[p+4], buf[p+5], buf[p+6], buf[p+7] };
            p += 8;
            const unsigned char pkAlgo = buf[p];
            p += 1;

            const bool algorithmMatches = ownAlgorithm == PGP_KEY_ALGORITHM_RSA ? pkAlgo == PGP_ALGO_RSA : pkAlgo == PGP_ALGO_ECDH;
            if (!algorithmMatches || std::memcmp(thisKeyId, ownSubkeyKeyId, 8) != 0)
            {
                pos = pkeskEnd;
                continue;
            }
            if (pkAlgo == PGP_ALGO_ECDH)
            {
                unsigned char ephemeralPublicKey[32];
                if (readNativePointMpi(buf, p, ephemeralPublicKey) && p < pkeskEnd)
                {
                    const std::size_t wrappedLength = buf[p++];
                    if (p + wrappedLength <= pkeskEnd)
                    {
                        const std::vector<unsigned char> wrapped(buf.begin() + p, buf.begin() + p + wrappedLength);
                        CryptoPP::x25519 dh;
                        unsigned char sharedSecret[32];
                        if (dh.Agree(sharedSecret, ownX25519PrivateKey, ephemeralPublicKey))
                        {
                            const std::vector<unsigned char> param = buildEcdhKdfParam(ownSubkeyFingerprint);
                            const std::vector<unsigned char> kek = computeEcdhKek(sharedSecret, param, 16);
                            std::vector<unsigned char> unwrapped;
                            if (kek.size() == 16 && aesKeyUnwrap(kek.data(), kek.size(), wrapped, unwrapped) && !unwrapped.empty())
                            {
                                const unsigned char padLength = unwrapped.back();
                                if (padLength >= 1 && padLength <= 8 && static_cast<std::size_t>(padLength) <= unwrapped.size())
                                {
                                    unwrapped.resize(unwrapped.size() - padLength);
                                    sessionPlain = unwrapped;
                                    found = true;
                                }
                            }
                        }
                    }
                }
            }
            else
            {
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
                if (!found)
                {
                    const CryptoPP::Integer cipherInt(&buf[p], byteLength);
                    const std::size_t modulusLength = rsaModulusByteLength(recipientPrivateKey.GetModulus());
                    std::vector<unsigned char> fixedCipher(modulusLength, 0);
                    cipherInt.Encode(fixedCipher.data(), modulusLength);
                    CryptoPP::RSAES<CryptoPP::PKCS1v15>::Decryptor decryptor(recipientPrivateKey);
                    std::vector<unsigned char> plain(decryptor.FixedMaxPlaintextLength());
                    CryptoPP::AutoSeededRandomPool rng;
                    const CryptoPP::DecodingResult decResult = decryptor.Decrypt(rng, fixedCipher.data(), fixedCipher.size(), plain.data());
                    if (decResult.isValidCoding)
                    {
                        plain.resize(decResult.messageLength);
                        sessionPlain = plain;
                        found = true;
                    }
                }
            }

            pos = pkeskEnd;
        }

        if (!found || sessionPlain.empty())
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
        bool seipPartial = false;
        if (!readPacketHeader(buf, pos, seipTag, seipBodyLength, static_cast<std::size_t>(-1), &seipPartial) || seipTag != PGP_TAG_SEIP)
        {
            return result;
        }
        if (pos >= buf.size() || buf[pos] != 1)
        {
            return result;
        }
        pos += 1;

        if (seipPartial)
        {
            // Partial-body-length SEIP (what GnuPG produces for anything past its output buffer):
            // seipBodyLength above is only the FIRST chunk. The total is not written anywhere, so
            // walk the chunk headers once to add it up, then rewind to the first ciphertext octet
            // and hand the streaming reader the chunk state instead of a leftover prefix -- the
            // prefix read above would otherwise have to be de-chunked here as well, for no gain.
            const unsigned long long bodyStartOffset = static_cast<unsigned long long>(pos - 1);
            unsigned long long totalPayload = 0;
            if (seipBodyLength < 1 || !scanPartialBodyTotalLength(inputFileHandle, bodyStartOffset, seipBodyLength, totalPayload) || totalPayload < 1)
            {
                return result;
            }

            LARGE_INTEGER moveTo;
            moveTo.QuadPart = static_cast<LONGLONG>(pos);
            if (!SetFilePointerEx(inputFileHandle, moveTo, nullptr, FILE_BEGIN))
            {
                return result;
            }

            result.sessionKey = sessionKey;
            result.encLength = static_cast<std::size_t>(totalPayload - 1);
            result.leftoverCipher.clear();
            result.seipPartial = true;
            result.seipChunkRemaining = seipBodyLength - 1; // the SEIP version octet came out of this same first chunk.
            result.seipFinalChunk = false;
            result.ok = true;
            return result;
        }

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

// ================================================================================================
// Minimal from-scratch BZip2 stream decoder -- RFC 4880's Compressed Data packet algorithm octet 3
// (section 9.3). Crypto++ 8.9.0 (vendored under 3rdParty/cryptopp890) never shipped BZip2 support
// (it was dropped from Crypto++ long before 8.x), and no other 3rdParty dependency in this repo
// vendors it either: Botan's own bzip2 wrapper (3rdParty/botan3130/src/lib/compression/bzip2) only
// links against an external system libbz2 ("<libs> all -> bz2" in its info.txt), which this repo
// does not carry. So this is a small self-contained decoder implementing exactly the bzip2 format
// (https://sourceware.org/bzip2/): Huffman-coded MTF/RLE2 symbol stream -> inverse Burrows-Wheeler
// transform (via the classic cumulative-count/"next" array technique) -> inverse initial RLE1.
// Decode-only (EncryptFileCompressed never produces BZip2, only ZIP/ZLIB -- see its own comment)
// and does not verify bzip2's own per-block/whole-stream CRC32 (the outer OpenPGP SEIP's SHA-1 MDC
// already covers end-to-end integrity for this engine's purposes) -- any malformed/corrupt bzip2
// stream still fails closed via a decode error, it just is not specifically diagnosed as a "bzip2
// CRC mismatch". Randomized blocks (a deprecated feature no encoder since bzip2 1.0.3, 2005, has
// produced) are rejected rather than derandomized.
// ================================================================================================

class Bzip2BitReader
{
public:
    Bzip2BitReader(const unsigned char* data, const std::size_t size) : data_(data), size_(size), bytePos_(0), bitBuffer_(0), bitCount_(0) {}

    bool ReadBit(unsigned int& outBit)
    {
        if (bitCount_ == 0)
        {
            if (bytePos_ >= size_)
            {
                return false;
            }
            bitBuffer_ = data_[bytePos_++];
            bitCount_ = 8;
        }
        --bitCount_;
        outBit = (bitBuffer_ >> bitCount_) & 1U;
        return true;
    }

    bool ReadBits(const unsigned int count, unsigned int& outValue)
    {
        outValue = 0;
        for (unsigned int i = 0; i < count; ++i)
        {
            unsigned int bit = 0;
            if (!ReadBit(bit))
            {
                return false;
            }
            outValue = (outValue << 1) | bit;
        }
        return true;
    }

    bool ReadBits64(const unsigned int count, unsigned long long& outValue)
    {
        outValue = 0;
        for (unsigned int i = 0; i < count; ++i)
        {
            unsigned int bit = 0;
            if (!ReadBit(bit))
            {
                return false;
            }
            outValue = (outValue << 1) | static_cast<unsigned long long>(bit);
        }
        return true;
    }

private:
    const unsigned char* data_;
    std::size_t size_;
    std::size_t bytePos_;
    unsigned int bitBuffer_;
    unsigned int bitCount_;
};
// -----------------------------------------------------------------------------

// Canonical Huffman decode table (limit/base/perm arrays) -- the classic bzip2/bzlib algorithm:
// perm[] lists symbols sorted by (codeLength, symbolValue); base[len]/limit[len] let getSymbol
// below decode bit-by-bit without a full tree. Lengths are 1..20 per the bzip2 format, so 24
// entries in base/limit comfortably covers every valid length plus its "len+1" lookups.
struct Bzip2HuffmanTable
{
    int minLen;
    int maxLen;
    int limit[24];
    int base[24];
    std::vector<int> perm;
};
// -----------------------------------------------------------------------------

bool bzip2BuildHuffmanTable(const std::vector<unsigned char>& lengths, const int alphaSize, Bzip2HuffmanTable& table)
{
    try
    {
        int minLen = 32;
        int maxLen = 0;
        for (int i = 0; i < alphaSize; ++i)
        {
            if (lengths[i] < minLen) { minLen = lengths[i]; }
            if (lengths[i] > maxLen) { maxLen = lengths[i]; }
        }
        if (minLen < 1 || maxLen > 20)
        {
            return false;
        }
        table.minLen = minLen;
        table.maxLen = maxLen;

        table.perm.assign(static_cast<std::size_t>(alphaSize), 0);
        int pp = 0;
        for (int len = minLen; len <= maxLen; ++len)
        {
            for (int i = 0; i < alphaSize; ++i)
            {
                if (lengths[i] == len)
                {
                    table.perm[pp++] = i;
                }
            }
        }

        for (int i = 0; i < 24; ++i)
        {
            table.base[i] = 0;
            table.limit[i] = 0;
        }
        for (int i = 0; i < alphaSize; ++i)
        {
            table.base[lengths[i] + 1]++;
        }
        for (int i = 1; i < 24; ++i)
        {
            table.base[i] += table.base[i - 1];
        }

        int vec = 0;
        for (int len = minLen; len <= maxLen; ++len)
        {
            vec += (table.base[len + 1] - table.base[len]);
            table.limit[len] = vec - 1;
            vec <<= 1;
        }
        for (int len = minLen + 1; len <= maxLen; ++len)
        {
            table.base[len] = ((table.limit[len - 1] + 1) << 1) - table.base[len];
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool bzip2GetSymbol(Bzip2BitReader& reader, const Bzip2HuffmanTable& table, int& outSymbol)
{
    unsigned int code = 0;
    if (!reader.ReadBits(static_cast<unsigned int>(table.minLen), code))
    {
        return false;
    }
    int len = table.minLen;
    while (true)
    {
        if (len > table.maxLen)
        {
            return false;
        }
        if (static_cast<int>(code) <= table.limit[len])
        {
            break;
        }
        unsigned int bit = 0;
        if (!reader.ReadBit(bit))
        {
            return false;
        }
        code = (code << 1) | bit;
        ++len;
    }
    const int index = static_cast<int>(code) - table.base[len];
    if (index < 0 || index >= static_cast<int>(table.perm.size()))
    {
        return false;
    }
    outSymbol = table.perm[index];
    return true;
}
// -----------------------------------------------------------------------------

// Decodes exactly one bzip2 block (everything after its 48-bit start-of-block magic, up to and
// including this block's own trailing structure -- there is none; the caller detects the next
// block/end-of-stream magic afterward) into blockOut, fully undoing MTF/RLE2, the BWT (via
// origPtr), and the initial RLE1 pass -- so blockOut ends up holding this block's share of the
// final decompressed bytes, in order.
bool bzip2DecodeBlock(Bzip2BitReader& reader, const unsigned int blockSize100k, std::vector<unsigned char>& blockOut)
{
    try
    {
        unsigned int blockCrc = 0;
        if (!reader.ReadBits(32, blockCrc))
        {
            return false;
        }

        unsigned int randomized = 0;
        if (!reader.ReadBits(1, randomized) || randomized != 0)
        {
            return false;
        }

        unsigned int origPtr = 0;
        if (!reader.ReadBits(24, origPtr))
        {
            return false;
        }

        // Mapping table (section-less, but see bzip2's own format notes): a 16-bit bitmap of
        // which 16-value groups are used, then a 16-bit per-value bitmap for each used group --
        // together giving the ascending list of distinct byte values actually present.
        unsigned int usedGroupsBits = 0;
        if (!reader.ReadBits(16, usedGroupsBits))
        {
            return false;
        }
        std::vector<unsigned char> symbolMap;
        for (int g = 0; g < 16; ++g)
        {
            if (((usedGroupsBits >> (15 - g)) & 1U) == 0)
            {
                continue;
            }
            unsigned int usedBitsInGroup = 0;
            if (!reader.ReadBits(16, usedBitsInGroup))
            {
                return false;
            }
            for (int k = 0; k < 16; ++k)
            {
                if (((usedBitsInGroup >> (15 - k)) & 1U) != 0)
                {
                    symbolMap.push_back(static_cast<unsigned char>(g * 16 + k));
                }
            }
        }
        const int nInUse = static_cast<int>(symbolMap.size());
        if (nInUse < 1)
        {
            return false;
        }
        const int alphaSize = nInUse + 2; // + RUNA/RUNB (0/1) folded in below, + trailing EOB.

        unsigned int numGroups = 0;
        if (!reader.ReadBits(3, numGroups) || numGroups < 2 || numGroups > 6)
        {
            return false;
        }
        unsigned int numSelectors = 0;
        if (!reader.ReadBits(15, numSelectors) || numSelectors == 0)
        {
            return false;
        }

        // Selectors: MTF-encoded (unary) indices into the numGroups Huffman tables, one per
        // 50-symbol group of the main symbol stream decoded further below.
        std::vector<unsigned char> mtfGroupPos(numGroups);
        for (unsigned int i = 0; i < numGroups; ++i)
        {
            mtfGroupPos[i] = static_cast<unsigned char>(i);
        }
        std::vector<unsigned char> selectors(numSelectors);
        for (unsigned int i = 0; i < numSelectors; ++i)
        {
            unsigned int j = 0;
            unsigned int bit = 0;
            while (true)
            {
                if (!reader.ReadBit(bit))
                {
                    return false;
                }
                if (bit == 0)
                {
                    break;
                }
                ++j;
                if (j >= numGroups)
                {
                    return false;
                }
            }
            const unsigned char value = mtfGroupPos[j];
            for (unsigned int k = j; k > 0; --k)
            {
                mtfGroupPos[k] = mtfGroupPos[k - 1];
            }
            mtfGroupPos[0] = value;
            selectors[i] = value;
        }

        // Per-group Huffman code lengths: a 5-bit starting length, then a delta-coded adjustment
        // (unary "keep going" bit + direction bit) per symbol in the alphabet.
        std::vector<Bzip2HuffmanTable> tables(numGroups);
        for (unsigned int g = 0; g < numGroups; ++g)
        {
            unsigned int curLen = 0;
            if (!reader.ReadBits(5, curLen))
            {
                return false;
            }
            std::vector<unsigned char> lengths(static_cast<std::size_t>(alphaSize));
            for (int sym = 0; sym < alphaSize; ++sym)
            {
                while (true)
                {
                    unsigned int bit = 0;
                    if (!reader.ReadBit(bit))
                    {
                        return false;
                    }
                    if (bit == 0)
                    {
                        break;
                    }
                    unsigned int adjust = 0;
                    if (!reader.ReadBit(adjust))
                    {
                        return false;
                    }
                    if (adjust == 0)
                    {
                        ++curLen;
                    }
                    else
                    {
                        if (curLen == 0)
                        {
                            return false;
                        }
                        --curLen;
                    }
                }
                if (curLen < 1 || curLen > 20)
                {
                    return false;
                }
                lengths[static_cast<std::size_t>(sym)] = static_cast<unsigned char>(curLen);
            }
            if (!bzip2BuildHuffmanTable(lengths, alphaSize, tables[g]))
            {
                return false;
            }
        }

        // Main symbol stream: MTF ranks with RUNA/RUNB bijective-base-2 run-length coding of
        // repeated MTF-front bytes, terminated by the EOB symbol (alphaSize - 1).
        std::vector<unsigned char> mtf(symbolMap);
        const unsigned long long maxBlockBytes = static_cast<unsigned long long>(blockSize100k) * 100000ULL + 4096ULL;
        blockOut.clear();
        unsigned int selectorIndex = 0;
        unsigned int groupSymbolsLeft = 0;
        const Bzip2HuffmanTable* currentTable = nullptr;
        unsigned long long runLength = 0;
        unsigned int runBit = 0;
        const int eobSymbol = alphaSize - 1;

        while (true)
        {
            if (groupSymbolsLeft == 0)
            {
                if (selectorIndex >= selectors.size())
                {
                    return false;
                }
                currentTable = &tables[selectors[selectorIndex++]];
                groupSymbolsLeft = 50;
            }
            --groupSymbolsLeft;

            int symbol = 0;
            if (!bzip2GetSymbol(reader, *currentTable, symbol))
            {
                return false;
            }

            if (symbol == 0 || symbol == 1) // RUNA / RUNB
            {
                runLength += (static_cast<unsigned long long>(symbol) + 1ULL) << runBit;
                ++runBit;
                if (runLength > maxBlockBytes)
                {
                    return false;
                }
                continue;
            }

            if (runLength > 0)
            {
                const unsigned char runByte = mtf[0];
                for (unsigned long long r = 0; r < runLength; ++r)
                {
                    blockOut.push_back(runByte);
                }
                runLength = 0;
                runBit = 0;
                if (blockOut.size() > maxBlockBytes)
                {
                    return false;
                }
            }

            if (symbol == eobSymbol)
            {
                break;
            }

            const int mtfIndex = symbol - 1;
            if (mtfIndex < 0 || mtfIndex >= nInUse)
            {
                return false;
            }
            const unsigned char value = mtf[static_cast<std::size_t>(mtfIndex)];
            for (int k = mtfIndex; k > 0; --k)
            {
                mtf[static_cast<std::size_t>(k)] = mtf[static_cast<std::size_t>(k - 1)];
            }
            mtf[0] = value;
            blockOut.push_back(value);
            if (blockOut.size() > maxBlockBytes)
            {
                return false;
            }
        }

        if (origPtr >= blockOut.size())
        {
            return false;
        }

        // Inverse Burrows-Wheeler transform: the classic cumulative-count "next" array technique
        // (equivalent to bzlib's own packed "tt" array, kept unpacked here for clarity).
        const std::size_t n = blockOut.size();
        std::vector<unsigned int> cumulative(257, 0);
        for (std::size_t i = 0; i < n; ++i)
        {
            cumulative[static_cast<std::size_t>(blockOut[i]) + 1]++;
        }
        for (int i = 1; i <= 256; ++i)
        {
            cumulative[static_cast<std::size_t>(i)] += cumulative[static_cast<std::size_t>(i - 1)];
        }
        std::vector<unsigned int> nextIndex(n);
        std::vector<unsigned int> cursor(cumulative.begin(), cumulative.begin() + 256);
        for (std::size_t i = 0; i < n; ++i)
        {
            const unsigned char ch = blockOut[i];
            nextIndex[cursor[ch]] = static_cast<unsigned int>(i);
            cursor[ch]++;
        }

        std::vector<unsigned char> bwtOutput(n);
        unsigned int tPos = nextIndex[origPtr];
        for (std::size_t k = 0; k < n; ++k)
        {
            bwtOutput[k] = blockOut[tPos];
            tPos = nextIndex[tPos];
        }

        // Undo the initial RLE1 pass: any run of 4 identical bytes is followed by a count byte
        // (0-255) of how many MORE repeats follow.
        std::vector<unsigned char> rle1Output;
        rle1Output.reserve(n);
        std::size_t i = 0;
        while (i < bwtOutput.size())
        {
            const unsigned char b = bwtOutput[i];
            std::size_t runCount = 1;
            while (runCount < 4 && i + runCount < bwtOutput.size() && bwtOutput[i + runCount] == b)
            {
                ++runCount;
            }
            for (std::size_t k = 0; k < runCount; ++k)
            {
                rle1Output.push_back(b);
            }
            i += runCount;
            if (runCount == 4)
            {
                if (i >= bwtOutput.size())
                {
                    return false;
                }
                const unsigned char extra = bwtOutput[i++];
                for (unsigned int k = 0; k < extra; ++k)
                {
                    rle1Output.push_back(b);
                }
            }
        }

        blockOut.swap(rle1Output);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Decodes a complete bzip2 stream (the "BZh" + level header, one or more compressed blocks, and
// the final end-of-stream marker + combined CRC) into output. See the banner comment above this
// section for why this exists instead of a Crypto++/Botan class, and for the CRC caveat.
bool bzip2DecompressBuffer(const std::vector<unsigned char>& input, std::vector<unsigned char>& output)
{
    try
    {
        if (input.size() < 4 || input[0] != 'B' || input[1] != 'Z' || input[2] != 'h' || input[3] < '1' || input[3] > '9')
        {
            return false;
        }
        const unsigned int blockSize100k = static_cast<unsigned int>(input[3] - '0');

        Bzip2BitReader reader(input.data() + 4, input.size() - 4);
        output.clear();

        const unsigned long long blockMagic = 0x314159265359ULL;
        const unsigned long long eosMagic = 0x177245385090ULL;

        while (true)
        {
            unsigned long long magic = 0;
            if (!reader.ReadBits64(48, magic))
            {
                return false;
            }
            if (magic == eosMagic)
            {
                unsigned int combinedCrc = 0;
                reader.ReadBits(32, combinedCrc); // best-effort only -- see banner comment above.
                break;
            }
            if (magic != blockMagic)
            {
                return false;
            }
            std::vector<unsigned char> blockOut;
            if (!bzip2DecodeBlock(reader, blockSize100k, blockOut))
            {
                return false;
            }
            output.insert(output.end(), blockOut.begin(), blockOut.end());
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Streams the SEIP body (CFB-decrypt + running MDC) into outputFileHandle. The inner packet may
// be a Literal Data packet (tag 11) or a Compressed Data packet (tag 8) containing one literal
// packet; ZIP and ZLIB are inflated incrementally so file size does not bound memory usage. BZip2
// (algorithm 3) is the one exception: bzip2DecompressBuffer's inverse-BWT step fundamentally needs
// the whole block decoded before it can emit a single output byte (see its own comment), and this
// engine's from-scratch decoder (see the banner comment above it) does not attempt incremental
// per-block bit-stream resumption -- so the entire Compressed Data packet body (the bzip2-
// compressed bytes, which is typically much smaller than the plaintext it expands to) is buffered
// before decoding, and the decompressed result is then handed to the same
// drainDecoded()/writeFileExact() output path in bounded chunks. This only affects algorithm 3;
// EncryptFileCompressed below never produces it, so this engine's own round-trip stays fully
// O(chunk) end to end -- the tradeoff is confined to reading BZip2 files from other producers.
//
// seipPartial/seipChunkRemaining/seipFinalChunk come straight from parseEncryptedFileHeader (see
// DecryptFileHeader) and describe partial-body-length framing (RFC 4880 section 4.2.2.4) on the
// SEIP packet itself: the chunk length octets sitting between runs of ciphertext are stepped over
// as the read position reaches each of them, so everything downstream -- including all four
// compression cases below -- still sees one flat stream of encLength ciphertext octets. Partial-
// body-length framing on the INNER packet (which GnuPG applies to the Literal Data packet when its
// own input size is unknown) is handled separately, further down, since those chunk headers are
// inside the encrypted -- and possibly compressed -- data rather than in the file's clear framing.
int decryptSeipBodyStreaming(HANDLE inputFileHandle, const std::vector<unsigned char>& leftoverCipher, const std::size_t encLength, const bool seipPartial, const std::size_t seipChunkRemaining, const bool seipFinalChunk, const unsigned char* sessionKey, const std::size_t sessionKeyLength, HANDLE outputFileHandle, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (encLength < 18 + 6 + 22 || leftoverCipher.size() > encLength)
        {
            return INVALID_DATA;
        }

        std::size_t cipherChunkRemaining = seipChunkRemaining;
        bool cipherFinalChunk = seipFinalChunk;

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
                std::size_t readCeiling = cipherRemaining;
                if (seipPartial)
                {
                    // Step over every chunk length header the read position has reached before
                    // taking any more ciphertext, and never read past the current chunk's end.
                    while (cipherChunkRemaining == 0)
                    {
                        if (cipherFinalChunk)
                        {
                            return false;
                        }
                        unsigned char chunkHeader[5] = { 0, 0, 0, 0, 0 };
                        if (!readFileExact(inputFileHandle, chunkHeader, 1))
                        {
                            return false;
                        }
                        const std::size_t chunkHeaderSize = newFormatBodyLengthHeaderSize(chunkHeader[0]);
                        if (chunkHeaderSize > 1 && !readFileExact(inputFileHandle, chunkHeader + 1, static_cast<DWORD>(chunkHeaderSize - 1)))
                        {
                            return false;
                        }
                        std::size_t decodedHeaderSize = 0;
                        std::size_t chunkLength = 0;
                        bool isPartial = false;
                        if (!decodeNewFormatBodyLength(chunkHeader, chunkHeaderSize, decodedHeaderSize, chunkLength, isPartial))
                        {
                            return false;
                        }
                        cipherChunkRemaining = chunkLength;
                        cipherFinalChunk = !isPartial;
                    }
                    if (readCeiling > cipherChunkRemaining)
                    {
                        readCeiling = cipherChunkRemaining;
                    }
                }
                const DWORD toRead = static_cast<DWORD>((readCeiling < cipherReadBuf.size()) ? readCeiling : cipherReadBuf.size());
                DWORD bytesRead = 0;
                if (!ReadFile(inputFileHandle, cipherReadBuf.data(), toRead, &bytesRead, nullptr) || bytesRead == 0)
                {
                    return false;
                }
                cipherRemaining -= bytesRead;
                if (seipPartial)
                {
                    cipherChunkRemaining -= bytesRead;
                }
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
        bool innerPartial = false;
        for (std::size_t probeSize = 8; probeSize <= 512 && !innerHeaderParsed; probeSize += 8)
        {
            if (!ensurePending(probeSize))
            {
                break;
            }
            const std::vector<unsigned char> probeBuf(pending.begin() + pendingPos, pending.begin() + pendingPos + probeSize);
            std::size_t probePos = 0;
            if (readPacketHeader(probeBuf, probePos, innerTag, innerBodyLength, static_cast<std::size_t>(-1), &innerPartial))
            {
                innerHeaderLength = probePos;
                innerHeaderParsed = true;
            }
        }
        if (!innerHeaderParsed)
        {
            return INVALID_DATA;
        }
        const unsigned char innerFirst = pending[pendingPos];
        const bool innerIndeterminate = (innerFirst & 0xC0) == 0x80 && (innerFirst & 0x03) == 3;
        consumeForHash(innerHeaderLength);
        if (innerIndeterminate)
        {
            if (streamPos > encLength - 22)
            {
                return INVALID_DATA;
            }
            innerBodyLength = encLength - 22 - streamPos;
        }

        // Partial-body-length framing on the inner packet: innerBodyLength above is only its FIRST
        // chunk, and the chunk length octets that separate the following chunks are part of the
        // decrypted stream (so they are MDC-hashed like every other body octet, but must not reach
        // the output file, the ZIP/ZLIB inflator, or the BZip2 accumulator). innerChunkRemaining/
        // innerFinalChunk track where the next such header sits; ensureInnerChunk steps over it the
        // moment the stream reaches it. Both stay inert for definite-length and old-format
        // indeterminate inner packets, which take exactly the same path through the loops below as
        // they always did.
        std::size_t innerChunkRemaining = innerPartial ? innerBodyLength : 0;
        bool innerFinalChunk = false;
        auto ensureInnerChunk = [&](void) -> bool
        {
            if (!innerPartial)
            {
                return true;
            }
            while (innerChunkRemaining == 0)
            {
                if (innerFinalChunk)
                {
                    return false;
                }
                if (!ensurePending(1))
                {
                    return false;
                }
                const std::size_t chunkHeaderSize = newFormatBodyLengthHeaderSize(pending[pendingPos]);
                if (!ensurePending(chunkHeaderSize))
                {
                    return false;
                }
                std::size_t decodedHeaderSize = 0;
                std::size_t chunkLength = 0;
                bool isPartial = false;
                if (!decodeNewFormatBodyLength(&pending[pendingPos], chunkHeaderSize, decodedHeaderSize, chunkLength, isPartial))
                {
                    return false;
                }
                consumeForHash(decodedHeaderSize);
                innerChunkRemaining = chunkLength;
                innerFinalChunk = !isPartial;
            }
            return true;
        };
        // The fixed-size prefix each inner packet type starts with (a Compressed Data packet's
        // algorithm octet, a Literal Data packet's format/filename/timestamp fields) is read out of
        // `pending` as one contiguous run below, so it must not straddle a chunk boundary. RFC 4880
        // section 4.2.2.4 requires the first partial chunk to be at least 512 octets, which is more
        // than any of those prefixes can ever need, so this only ever rejects malformed input.
        auto innerPrefixFitsInChunk = [&](const std::size_t prefixLength) -> bool
        {
            return !innerPartial || innerChunkRemaining >= prefixLength;
        };

        if (innerTag == PGP_TAG_COMPRESSED_DATA)
        {
            if (innerBodyLength < 1 || (!innerPartial && innerBodyLength > mdcHashOffset - streamPos - 2))
            {
                return INVALID_DATA;
            }
            if (!ensurePending(1) || !innerPrefixFitsInChunk(1))
            {
                return INVALID_DATA;
            }
            const unsigned char algorithm = pending[pendingPos];
            consumeForHash(1);
            if (innerPartial)
            {
                innerChunkRemaining -= 1;
            }
            if (algorithm > 3)
            {
                return NOT_IMPLEMENTED;
            }
            std::size_t compressedRemaining = innerBodyLength - 1;
            CryptoPP::ByteQueue* decodedQueue = new CryptoPP::ByteQueue();
            std::unique_ptr<CryptoPP::BufferedTransformation> inflator;
            std::vector<unsigned char> bzip2CompressedAccumulator; // only filled when algorithm == 3.
            if (algorithm == 1)
            {
                inflator.reset(new CryptoPP::Inflator(decodedQueue));
            }
            else if (algorithm == 2)
            {
                inflator.reset(new CryptoPP::ZlibDecompressor(decodedQueue));
            }
            else
            {
                // algorithm == 0 (uncompressed): decodedQueue itself acts as the "inflator" (Put()
                // just enqueues verbatim). algorithm == 3 (BZip2) also reaches this branch purely so
                // decodedQueue's lifetime is owned by `inflator` for cleanup -- the loop below never
                // calls inflator->Put()/MessageEnd() for algorithm 3, it accumulates the compressed
                // bytes into bzip2CompressedAccumulator instead and decodes them in one pass
                // afterward (see bzip2DecompressBuffer's own comment for why).
                inflator.reset(decodedQueue);
            }

            std::vector<unsigned char> decodedPending;
            bool literalHeaderParsed = false;
            bool literalPrefixParsed = false;
            bool literalIndeterminate = false;
            std::size_t literalHeaderEnd = 0;
            std::size_t literalBodyLength = 0;
            std::size_t contentRemaining = 0;
            unsigned long long processedBytes = 0;
            // Partial-body-length framing on the Literal Data packet that comes back out of the
            // decompressor -- what GnuPG emits whenever it streamed the plaintext in from a source
            // of unknown size (piped stdin). This is framing INSIDE the decompressed stream, so it
            // is independent of which of the four compression algorithms produced that stream:
            // ZIP/ZLIB arrive here incrementally through decodedQueue, BZip2 arrives in one post-
            // loop burst, and either way literalRawPending holds the still-framed tail while the
            // chunk headers are stripped out of it into decodedPending, which therefore always
            // holds plain content octets exactly like in the non-partial case. A partial-length
            // literal also has no total length anywhere, so it is treated as indeterminate too.
            bool literalPartial = false;
            bool literalFinalChunk = false;
            std::size_t literalChunkRemaining = 0;
            std::vector<unsigned char> literalRawPending;
            auto drainDecoded = [&]() -> int
            {
                const std::size_t available = static_cast<std::size_t>(decodedQueue->MaxRetrievable());
                if (available > 0)
                {
                    std::vector<unsigned char>& decodedSink = literalPartial ? literalRawPending : decodedPending;
                    const std::size_t oldSize = decodedSink.size();
                    decodedSink.resize(oldSize + available);
                    decodedQueue->Get(decodedSink.data() + oldSize, available);
                }
                if (literalPartial && !dechunkPartialBody(literalRawPending, literalChunkRemaining, literalFinalChunk, decodedPending))
                {
                    return INVALID_DATA;
                }
                if (!literalHeaderParsed)
                {
                    if (decodedPending.empty())
                    {
                        return NO_ERROR;
                    }
                    std::size_t pos = 0;
                    unsigned char tag = 0;
                    bool isPartial = false;
                    if (!readPacketHeader(decodedPending, pos, tag, literalBodyLength, static_cast<std::size_t>(-1), &isPartial))
                    {
                        return decodedPending.size() > 512 ? INVALID_DATA : NO_ERROR;
                    }
                    if (tag != PGP_TAG_LITERAL_DATA)
                    {
                        return INVALID_DATA;
                    }
                    const unsigned char first = decodedPending[0];
                    literalIndeterminate = (first & 0xC0) == 0x80 && (first & 0x03) == 3;
                    if (isPartial)
                    {
                        literalPartial = true;
                        literalIndeterminate = true;
                        literalChunkRemaining = literalBodyLength; // the header carried the FIRST chunk's length only.
                        literalFinalChunk = false;
                        literalRawPending.assign(decodedPending.begin() + pos, decodedPending.end());
                        decodedPending.resize(pos);
                        if (!dechunkPartialBody(literalRawPending, literalChunkRemaining, literalFinalChunk, decodedPending))
                        {
                            return INVALID_DATA;
                        }
                    }
                    literalHeaderParsed = true;
                    literalHeaderEnd = pos;
                }
                if (!literalPrefixParsed)
                {
                    if (decodedPending.size() < literalHeaderEnd + 2)
                    {
                        return NO_ERROR;
                    }
                    const std::size_t prefixLength = 2 + static_cast<std::size_t>(decodedPending[literalHeaderEnd + 1]) + 4;
                    if (!literalIndeterminate && literalBodyLength < prefixLength)
                    {
                        return INVALID_DATA;
                    }
                    if (decodedPending.size() < literalHeaderEnd + prefixLength)
                    {
                        return NO_ERROR;
                    }
                    contentRemaining = literalIndeterminate ? 0 : literalBodyLength - prefixLength;
                    decodedPending.erase(decodedPending.begin(), decodedPending.begin() + literalHeaderEnd + prefixLength);
                    literalPrefixParsed = true;
                }
                if (!literalIndeterminate && decodedPending.size() > contentRemaining)
                {
                    return INVALID_DATA;
                }
                if (!decodedPending.empty())
                {
                    if (!writeFileExact(outputFileHandle, decodedPending.data(), static_cast<DWORD>(decodedPending.size())))
                    {
                        return FILE_IO_ERROR;
                    }
                    processedBytes += decodedPending.size();
                    if (!literalIndeterminate)
                    {
                        contentRemaining -= decodedPending.size();
                    }
                    decodedPending.clear();
                    if (onProgress)
                    {
                        const unsigned long long total = literalIndeterminate ? 0 : processedBytes + contentRemaining;
                        const double percentage = total > 0 ? (static_cast<double>(processedBytes) / static_cast<double>(total)) * 100.0 : 0.0;
                        if (!onProgress(processedBytes, total, percentage, progressUserData))
                        {
                            return OPERATION_CANCELLED;
                        }
                    }
                }
                return NO_ERROR;
            };

            // Feeds the Compressed Data packet's body to whichever decoder `algorithm` selected.
            // The partial-body-length variants differ only in where the body ENDS and in having to
            // step over a chunk length header now and then -- what is done with each run of body
            // octets (ZIP/ZLIB straight into the inflator, BZip2 into the accumulator, algorithm 0
            // verbatim into decodedQueue) is unchanged and applies identically either way, because
            // ensureInnerChunk/innerChunkRemaining guarantee takeNow never spans a chunk header.
            while (innerPartial ? !(innerFinalChunk && innerChunkRemaining == 0) : (compressedRemaining > 0))
            {
                if (!ensureInnerChunk())
                {
                    return INVALID_DATA;
                }
                if (!ensurePending(1))
                {
                    return INVALID_DATA;
                }
                const std::size_t available = pending.size() - pendingPos;
                const std::size_t bodyRemaining = innerPartial ? innerChunkRemaining : compressedRemaining;
                const std::size_t takeNow = std::min<std::size_t>(std::min<std::size_t>(available, bodyRemaining), 4096);
                if (algorithm == 3)
                {
                    bzip2CompressedAccumulator.insert(bzip2CompressedAccumulator.end(), pending.begin() + pendingPos, pending.begin() + pendingPos + takeNow);
                }
                else
                {
                    try
                    {
                        inflator->Put(&pending[pendingPos], takeNow);
                    }
                    catch (const CryptoPP::Exception&)
                    {
                        return INVALID_DATA;
                    }
                }
                consumeForHash(takeNow);
                if (innerPartial)
                {
                    innerChunkRemaining -= takeNow;
                }
                else
                {
                    compressedRemaining -= takeNow;
                }
                if (algorithm != 3)
                {
                    const int status = drainDecoded();
                    if (status != NO_ERROR)
                    {
                        return status;
                    }
                }
                if (pendingPos > PGP_FILE_CHUNK_SIZE)
                {
                    pending.erase(pending.begin(), pending.begin() + pendingPos);
                    pendingPos = 0;
                }
            }
            if (algorithm == 3)
            {
                std::vector<unsigned char> bzip2Decompressed;
                if (!bzip2DecompressBuffer(bzip2CompressedAccumulator, bzip2Decompressed))
                {
                    return INVALID_DATA;
                }
                bzip2CompressedAccumulator.clear();
                bzip2CompressedAccumulator.shrink_to_fit();
                std::size_t bzOffset = 0;
                const std::size_t bzChunkSize = 65536;
                do
                {
                    const std::size_t take = std::min<std::size_t>(bzChunkSize, bzip2Decompressed.size() - bzOffset);
                    if (take > 0)
                    {
                        decodedQueue->Put(&bzip2Decompressed[bzOffset], take);
                        bzOffset += take;
                    }
                    const int status = drainDecoded();
                    if (status != NO_ERROR)
                    {
                        return status;
                    }
                } while (bzOffset < bzip2Decompressed.size());
                if (!literalPrefixParsed || (!literalIndeterminate && contentRemaining != 0))
                {
                    return INVALID_DATA;
                }
            }
            else
            {
                try
                {
                    inflator->MessageEnd();
                }
                catch (const CryptoPP::Exception&)
                {
                    return INVALID_DATA;
                }
                const int status = drainDecoded();
                if (status != NO_ERROR || !literalPrefixParsed || (!literalIndeterminate && contentRemaining != 0))
                {
                    return status != NO_ERROR ? status : INVALID_DATA;
                }
            }
            // A partial-body-length literal packet must have ended on its terminating chunk with
            // every framed octet accounted for -- otherwise the message was truncated. Checked once
            // here rather than inside each branch above, since it holds for all four compression
            // algorithms alike (the framing being checked lives in the decompressed stream, not in
            // whatever encoding delivered it).
            if (literalPartial && (!literalFinalChunk || literalChunkRemaining != 0 || !literalRawPending.empty()))
            {
                return INVALID_DATA;
            }
        }
        else if (innerTag == PGP_TAG_LITERAL_DATA)
        {
            if (!ensurePending(2))
            {
                return INVALID_DATA;
            }
            const unsigned char filenameLength = pending[pendingPos + 1];
            const std::size_t literalHeaderTotal = 2 + static_cast<std::size_t>(filenameLength) + 4;
            if (!innerPrefixFitsInChunk(literalHeaderTotal))
            {
                return INVALID_DATA;
            }
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
            if (innerBodyLength < literalHeaderTotal)
            {
                return INVALID_DATA;
            }
            // A partial-body-length literal announces no total size, so there is nothing to count
            // down and nothing to report a percentage against (same as the old-format
            // indeterminate case the compressed branch above already handles): the content simply
            // runs until the terminating chunk is exhausted.
            std::size_t contentRemaining = innerPartial ? 0 : (innerBodyLength - literalHeaderTotal);
            if (innerPartial)
            {
                innerChunkRemaining -= literalHeaderTotal;
            }
            const unsigned long long totalContentBytes = innerPartial ? 0 : static_cast<unsigned long long>(contentRemaining);
            unsigned long long processedBytes = 0;
            while (innerPartial ? !(innerFinalChunk && innerChunkRemaining == 0) : (contentRemaining > 0))
            {
                if (!ensureInnerChunk())
                {
                    return INVALID_DATA;
                }
                if (!ensurePending(1))
                {
                    return INVALID_DATA;
                }
                const std::size_t available = pending.size() - pendingPos;
                const std::size_t bodyRemaining = innerPartial ? innerChunkRemaining : contentRemaining;
                const std::size_t wantBytes = (bodyRemaining < PGP_FILE_CHUNK_SIZE) ? bodyRemaining : PGP_FILE_CHUNK_SIZE;
                const std::size_t takeNow = (available < wantBytes) ? available : wantBytes;
                if (!writeFileExact(outputFileHandle, &pending[pendingPos], static_cast<DWORD>(takeNow)))
                {
                    return FILE_IO_ERROR;
                }
                consumeForHash(takeNow);
                if (innerPartial)
                {
                    innerChunkRemaining -= takeNow;
                }
                else
                {
                    contentRemaining -= takeNow;
                }
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
        }
        else
        {
            return NOT_IMPLEMENTED;
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

// ================================================================================================
// Peer/recipient public key block parsing -- shared by ImportPeerPublicKey (wants both the master
// verify key and the encryption subkey) and ImportAdditionalRecipientPublicKey (wants only the
// encryption subkey). Each key packet's own algorithm octet is detected independently (RSA, or
// EdDSA/ECDH), so a single armored/binary block's master and subkey may even use different
// algorithm families in principle, though this engine and GnuPG's own "ed25519" identities always
// keep both in the same family.
// ================================================================================================

struct ParsedPeerPublicKeyBlock
{
    bool haveMaster;
    PgpKeyAlgorithm masterAlgorithm;
    CryptoPP::RSA::PublicKey masterRsaKey;
    unsigned char masterEd25519Key[32];
    unsigned char masterKeyId[8];

    bool haveSubkey;
    PgpKeyAlgorithm subkeyAlgorithm;
    CryptoPP::RSA::PublicKey subkeyRsaKey;
    unsigned char subkeyX25519Key[32];
    unsigned char subkeyKeyId[8];
    unsigned char subkeyFingerprint[20];

    ParsedPeerPublicKeyBlock() : haveMaster(false), masterAlgorithm(PGP_KEY_ALGORITHM_RSA), haveSubkey(false), subkeyAlgorithm(PGP_KEY_ALGORITHM_RSA)
    {
        std::memset(masterEd25519Key, 0, 32);
        std::memset(masterKeyId, 0, 8);
        std::memset(subkeyX25519Key, 0, 32);
        std::memset(subkeyKeyId, 0, 8);
        std::memset(subkeyFingerprint, 0, 20);
    }
};
// -----------------------------------------------------------------------------

bool decodeKeyBlockToBinary(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize, std::vector<unsigned char>& binary)
{
    try
    {
        if (keyBlockBufferSize >= 5 && std::memcmp(keyBlockBuffer, "-----", 5) == 0)
        {
            const std::string armored(reinterpret_cast<const char*>(keyBlockBuffer), static_cast<std::size_t>(keyBlockBufferSize));
            std::string blockType;
            return armorDecode(armored, blockType, binary);
        }
        binary.assign(keyBlockBuffer, keyBlockBuffer + keyBlockBufferSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool parsePeerPublicKeyBlock(const std::vector<unsigned char>& binary, ParsedPeerPublicKeyBlock& out)
{
    try
    {
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

            if (tag != PGP_TAG_PUBLIC_KEY && tag != PGP_TAG_PUBLIC_SUBKEY)
            {
                continue;
            }
            const bool isMaster = (tag == PGP_TAG_PUBLIC_KEY);
            if ((isMaster && out.haveMaster) || (!isMaster && out.haveSubkey))
            {
                continue;
            }
            if (body.size() < 6)
            {
                continue;
            }
            const unsigned char algo = body[5];

            if (algo == PGP_ALGO_RSA)
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
                if (isMaster)
                {
                    out.masterAlgorithm = PGP_KEY_ALGORITHM_RSA;
                    out.masterRsaKey = key;
                    std::memcpy(out.masterKeyId, keyId, 8);
                    out.haveMaster = true;
                }
                else
                {
                    out.subkeyAlgorithm = PGP_KEY_ALGORITHM_RSA;
                    out.subkeyRsaKey = key;
                    std::memcpy(out.subkeyKeyId, keyId, 8);
                    out.haveSubkey = true;
                }
            }
            else if (algo == PGP_ALGO_EDDSA && isMaster)
            {
                unsigned char point[32];
                unsigned char keyId[8];
                if (!parseEd25519PublicKeyPacketBody(body, point, keyId))
                {
                    continue;
                }
                out.masterAlgorithm = PGP_KEY_ALGORITHM_ED25519_X25519;
                std::memcpy(out.masterEd25519Key, point, 32);
                std::memcpy(out.masterKeyId, keyId, 8);
                out.haveMaster = true;
            }
            else if (algo == PGP_ALGO_ECDH && !isMaster)
            {
                unsigned char point[32];
                unsigned char keyId[8];
                unsigned char fingerprint[20];
                if (!parseX25519PublicKeyPacketBody(body, point, keyId, fingerprint))
                {
                    continue;
                }
                out.subkeyAlgorithm = PGP_KEY_ALGORITHM_ED25519_X25519;
                std::memcpy(out.subkeyX25519Key, point, 32);
                std::memcpy(out.subkeyKeyId, keyId, 8);
                std::memcpy(out.subkeyFingerprint, fingerprint, 20);
                out.haveSubkey = true;
            }
        }

        if (!out.haveMaster)
        {
            return false;
        }
        // No separate encryption subkey found (e.g. a bare master-key-only block) -- mirror the
        // pre-multi-recipient/pre-ECC behavior of falling back to encrypting to the master key
        // itself, but only when the master is RSA (an Ed25519 master key cannot encrypt -- RFC
        // 4880 key flags reserve that to Encrypt-flagged keys, i.e. an X25519 subkey, which by
        // construction never doubles as a signing master here).
        if (!out.haveSubkey && out.masterAlgorithm == PGP_KEY_ALGORITHM_RSA)
        {
            out.subkeyAlgorithm = PGP_KEY_ALGORITHM_RSA;
            out.subkeyRsaKey = out.masterRsaKey;
            std::memcpy(out.subkeyKeyId, out.masterKeyId, 8);
            out.haveSubkey = true;
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
// Read-only message inspection -- the shared machinery behind CPgpEngine's IsPublicKeyEncrypted/
// IsPasswordEncrypted/IsIntegrityProtected/GetCompression/ListEncryptionKeyIds/ListSigningKeyIds/
// ListSignatures methods (see PgpEngine.h for what each of them promises). ONE packet walker feeds
// all seven, and it is deliberately built on the same readPacketHeader/reassemblePartialBodyLengths
// primitives every other reader in this file uses rather than a second, simpler parser of its own:
// a naive walker would silently mis-handle old-format headers, indeterminate lengths and
// partial-body-length framing that the real readers already cope with, and would then disagree with
// DecryptBuffer/DecryptFile about the very same bytes.
//
// Nothing here decrypts or verifies anything -- the encrypted-data packets (SEIP/AEAD/SED) are
// noted and then stepped over, never opened.
// ================================================================================================

struct PgpInspectedSignature
{
    bool haveIssuerKeyId;
    unsigned char issuerKeyId[8];
    unsigned char signatureType;
    unsigned char hashAlgorithm;

    PgpInspectedSignature() : haveIssuerKeyId(false), signatureType(0), hashAlgorithm(0)
    {
        std::memset(issuerKeyId, 0, 8);
    }
};
// -----------------------------------------------------------------------------

struct PgpInspectedMessage
{
    bool sawAnyPacket;
    bool hasPkesk;
    bool hasSkesk;
    bool hasIntegrityProtectedData;   // SEIP (tag 18) or AEAD (tag 20).
    bool hasUnprotectedEncryptedData; // SED (tag 9), the obsolete MDC-less packet.
    bool hasCompressedData;
    unsigned char compressionAlgorithm;
    std::vector< std::vector<unsigned char> > recipientKeyIds; // one 8-byte entry per PKESK, in message order.
    std::vector<PgpInspectedSignature> signatures;             // tag 2 and tag 4 packets, in message order.

    PgpInspectedMessage() : sawAnyPacket(false), hasPkesk(false), hasSkesk(false),
                            hasIntegrityProtectedData(false), hasUnprotectedEncryptedData(false),
                            hasCompressedData(false), compressionAlgorithm(0)
    {
    }
};
// -----------------------------------------------------------------------------

// RFC 4880 section 5.2.3.1 signature SUBPACKET length -- deliberately NOT routed through
// decodeNewFormatBodyLength above, because the two encodings differ exactly where it matters: a
// subpacket's two-octet form covers a first octet of 192..254, whereas a packet BODY length
// reserves 224..254 for partial lengths instead. Reusing the body-length decoder here would decode
// every subpacket of length 8384..65535 as a bogus partial chunk.
bool readSignatureSubpacketLength(const std::vector<unsigned char>& data, std::size_t& pos, const std::size_t end, std::size_t& lengthOut)
{
    try
    {
        if (pos >= end)
        {
            return false;
        }
        const unsigned char first = data[pos];
        if (first < 192)
        {
            lengthOut = first;
            pos += 1;
            return true;
        }
        if (first < 255)
        {
            if (pos + 1 >= end)
            {
                return false;
            }
            lengthOut = (static_cast<std::size_t>(first - 192) << 8) + static_cast<std::size_t>(data[pos + 1]) + 192;
            pos += 2;
            return true;
        }
        if (pos + 4 >= end)
        {
            return false;
        }
        lengthOut = (static_cast<std::size_t>(data[pos + 1]) << 24) | (static_cast<std::size_t>(data[pos + 2]) << 16) |
                    (static_cast<std::size_t>(data[pos + 3]) << 8)  |  static_cast<std::size_t>(data[pos + 4]);
        pos += 5;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Scans one signature subpacket area (data[begin, end), either the hashed or the unhashed one) for
// the issuer's Key ID. An explicit Issuer Key ID subpacket (type 16) wins when present; otherwise
// the Key ID is derived from an Issuer Fingerprint subpacket (type 33), which is where modern
// GnuPG puts the issuer in the HASHED area -- for a v4 fingerprint the Key ID is its low 8 bytes
// (RFC 4880 section 12.2), for the 32-byte v5/v6 fingerprints it is the leading 8 (crypto-refresh).
bool findIssuerKeyIdInSubpackets(const std::vector<unsigned char>& data, const std::size_t begin, const std::size_t end, unsigned char keyIdOut[8])
{
    try
    {
        bool found = false;
        bool foundExplicitIssuerSubpacket = false;
        std::size_t pos = begin;
        while (pos < end)
        {
            std::size_t subpacketLength = 0;
            if (!readSignatureSubpacketLength(data, pos, end, subpacketLength) || subpacketLength == 0 || pos + subpacketLength > end)
            {
                break;
            }
            const unsigned char subpacketType = static_cast<unsigned char>(data[pos] & 0x7F);
            const std::size_t bodyBegin = pos + 1;
            const std::size_t bodyLength = subpacketLength - 1;

            if (subpacketType == 16 && bodyLength == 8 && !foundExplicitIssuerSubpacket)
            {
                std::memcpy(keyIdOut, &data[bodyBegin], 8);
                found = true;
                foundExplicitIssuerSubpacket = true;
            }
            else if (subpacketType == 33 && !found && bodyLength >= 21 && data[bodyBegin] == 4)
            {
                std::memcpy(keyIdOut, &data[bodyBegin + 13], 8);
                found = true;
            }
            else if (subpacketType == 33 && !found && bodyLength >= 33 && (data[bodyBegin] == 5 || data[bodyBegin] == 6))
            {
                std::memcpy(keyIdOut, &data[bodyBegin + 1], 8);
                found = true;
            }

            pos += subpacketLength;
        }
        return found;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Version-tolerant, algorithm-agnostic signature-packet reader for inspection only -- unlike
// parseSignaturePacketBody above (which exists to VERIFY, and therefore rejects anything outside
// this engine's own two supported RSA/SHA-256 and EdDSA/SHA-512 combinations), this one reports
// whatever signature type, hash algorithm and issuer a foreign producer wrote, without judging
// them. Returns false for a signature version whose field layout is not known here (anything but
// v3 and v4), so both List* methods skip exactly the same packets and their counts stay in step.
bool inspectSignaturePacketBody(const std::vector<unsigned char>& body, PgpInspectedSignature& out)
{
    try
    {
        if (body.empty())
        {
            return false;
        }

        if (body[0] == 3)
        {
            // v3 (RFC 4880 section 5.2.2): version, hashed-material length (always 5), signature
            // type, 4-octet creation time, 8-octet issuer Key ID, public-key algorithm, hash
            // algorithm -- the issuer sits in the packet itself, with no subpackets involved.
            if (body.size() < 17 || body[1] != 5)
            {
                return false;
            }
            out.signatureType = body[2];
            std::memcpy(out.issuerKeyId, &body[7], 8);
            out.haveIssuerKeyId = true;
            out.hashAlgorithm = body[16];
            return true;
        }

        if (body[0] == 4)
        {
            if (body.size() < 6)
            {
                return false;
            }
            out.signatureType = body[1];
            out.hashAlgorithm = body[3];

            std::size_t pos = 4;
            const std::size_t hashedLength = readBigEndian16(body, pos);
            pos += 2;
            if (pos + hashedLength > body.size())
            {
                return false;
            }
            const std::size_t hashedEnd = pos + hashedLength;
            out.haveIssuerKeyId = findIssuerKeyIdInSubpackets(body, pos, hashedEnd, out.issuerKeyId);
            pos = hashedEnd;

            if (!out.haveIssuerKeyId && pos + 2 <= body.size())
            {
                const std::size_t unhashedLength = readBigEndian16(body, pos);
                pos += 2;
                if (pos + unhashedLength <= body.size())
                {
                    out.haveIssuerKeyId = findIssuerKeyIdInSubpackets(body, pos, pos + unhashedLength, out.issuerKeyId);
                }
            }
            return true;
        }

        return false;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Decompresses a Compressed Data packet body (algorithm octet already stripped) so the inspection
// walker can keep walking the packets nested inside it. Handles the same four encodings
// DecryptFile/DecryptBuffer read (uncompressed/ZIP/ZLIB/BZip2, RFC 4880 section 9.3); anything
// else simply returns false and the nested packets stay unreported, which is honest rather than
// fatal -- the enclosing Compressed Data packet's own algorithm octet was already recorded.
bool decompressCompressedDataBodyForInspection(const unsigned char compressionAlgorithm, const unsigned char* body, const std::size_t bodySize, std::vector<unsigned char>& out)
{
    try
    {
        if (body == nullptr)
        {
            return false;
        }
        if (compressionAlgorithm == 0)
        {
            out.assign(body, body + bodySize);
            return true;
        }
        if (compressionAlgorithm == 1)
        {
            std::string decompressed;
            CryptoPP::Inflator inflator(new CryptoPP::StringSink(decompressed));
            inflator.Put(body, bodySize);
            inflator.MessageEnd();
            out.assign(decompressed.begin(), decompressed.end());
            return true;
        }
        if (compressionAlgorithm == 2)
        {
            std::string decompressed;
            CryptoPP::ZlibDecompressor inflator(new CryptoPP::StringSink(decompressed));
            inflator.Put(body, bodySize);
            inflator.MessageEnd();
            out.assign(decompressed.begin(), decompressed.end());
            return true;
        }
        if (compressionAlgorithm == 3)
        {
            const std::vector<unsigned char> compressed(body, body + bodySize);
            return bzip2DecompressBuffer(compressed, out);
        }
        return false;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

// Walks data[begin, end) as a sequence of whole OpenPGP packets, recording everything the seven
// inspection methods need. depth bounds the recursion into Compressed Data packets (a hostile or
// simply broken input could otherwise nest them without end); 3 is far beyond anything a real
// producer writes, where the deepest legitimate nesting is compressed -> literal.
void inspectPacketSequence(const std::vector<unsigned char>& data, const std::size_t begin, const std::size_t end, const int depth, PgpInspectedMessage& out)
{
    try
    {
        std::size_t pos = begin;
        while (pos < end)
        {
            unsigned char tag = 0;
            std::size_t bodyLength = 0;
            if (!readPacketHeader(data, pos, tag, bodyLength, end))
            {
                break;
            }
            if (bodyLength > end - pos)
            {
                break;
            }
            const std::size_t bodyBegin = pos;
            const std::size_t bodyEnd = pos + bodyLength;
            out.sawAnyPacket = true;

            if (tag == PGP_TAG_PKESK)
            {
                out.hasPkesk = true;
                // v3 PKESK (RFC 4880 section 5.1, the only version any producer writes today):
                // version octet, 8-octet recipient Key ID, public-key algorithm, then the
                // algorithm-specific session-key material this inspector never touches. A v6
                // PKESK identifies its recipient by fingerprint instead and is deliberately not
                // decoded here -- the packet is still counted as public-key encrypted.
                if (bodyLength >= 10 && data[bodyBegin] == 3)
                {
                    out.recipientKeyIds.push_back(std::vector<unsigned char>(data.begin() + bodyBegin + 1, data.begin() + bodyBegin + 9));
                }
            }
            else if (tag == PGP_TAG_SKESK)
            {
                out.hasSkesk = true;
            }
            else if (tag == PGP_TAG_SEIP || tag == PGP_TAG_AEAD)
            {
                out.hasIntegrityProtectedData = true;
            }
            else if (tag == PGP_TAG_SED)
            {
                out.hasUnprotectedEncryptedData = true;
            }
            else if (tag == PGP_TAG_SIGNATURE)
            {
                const std::vector<unsigned char> body(data.begin() + bodyBegin, data.begin() + bodyEnd);
                PgpInspectedSignature signature;
                if (inspectSignaturePacketBody(body, signature))
                {
                    out.signatures.push_back(signature);
                }
            }
            else if (tag == PGP_TAG_ONE_PASS_SIG)
            {
                // RFC 4880 section 5.4: version, signature type, hash algorithm, public-key
                // algorithm, 8-octet issuer Key ID, "nested" flag. This engine never WRITES one
                // (there is no one-pass signing API), but real GnuPG puts one in front of a
                // signed document, so it is read and reported like any other signature.
                if (bodyLength >= 13 && data[bodyBegin] == 3)
                {
                    PgpInspectedSignature signature;
                    signature.signatureType = data[bodyBegin + 1];
                    signature.hashAlgorithm = data[bodyBegin + 2];
                    std::memcpy(signature.issuerKeyId, &data[bodyBegin + 4], 8);
                    signature.haveIssuerKeyId = true;
                    out.signatures.push_back(signature);
                }
            }
            else if (tag == PGP_TAG_COMPRESSED_DATA)
            {
                if (bodyLength >= 1)
                {
                    if (!out.hasCompressedData)
                    {
                        out.hasCompressedData = true;
                        out.compressionAlgorithm = data[bodyBegin];
                    }
                    if (depth > 0)
                    {
                        std::vector<unsigned char> decompressed;
                        if (decompressCompressedDataBodyForInspection(data[bodyBegin], &data[bodyBegin] + 1, bodyLength - 1, decompressed) && !decompressed.empty())
                        {
                            std::vector<unsigned char> reassembledInner;
                            if (reassemblePartialBodyLengths(decompressed, reassembledInner))
                            {
                                decompressed.swap(reassembledInner);
                            }
                            inspectPacketSequence(decompressed, 0, decompressed.size(), depth - 1, out);
                        }
                    }
                }
            }

            pos = bodyEnd;
        }
    }
    catch (...)
    {
    }
}
// -----------------------------------------------------------------------------

// Turns whatever the caller handed an inspection method into raw OpenPGP packet bytes: raw binary
// straight through, an ASCII-armored block decoded (same auto-detection decodeKeyBlockToBinary
// uses for key blocks), and a clear-signed message reduced to its trailing signature block -- the
// only part of a clear-signed message that IS OpenPGP packets at all, the rest being plain text.
bool decodeInspectionInputToBinary(const unsigned char* inputBuffer, const int inputBufferSize, std::vector<unsigned char>& binary)
{
    try
    {
        if (inputBuffer == nullptr || inputBufferSize <= 0)
        {
            return false;
        }
        if (inputBufferSize >= 5 && std::memcmp(inputBuffer, "-----", 5) == 0)
        {
            const std::string text(reinterpret_cast<const char*>(inputBuffer), static_cast<std::size_t>(inputBufferSize));
            std::string blockType;
            if (text.compare(0, 34, "-----BEGIN PGP SIGNED MESSAGE-----") == 0)
            {
                const std::size_t sigBeginPos = text.find("-----BEGIN PGP SIGNATURE-----");
                if (sigBeginPos == std::string::npos)
                {
                    return false;
                }
                return armorDecode(text.substr(sigBeginPos), blockType, binary);
            }
            return armorDecode(text, blockType, binary);
        }
        binary.assign(inputBuffer, inputBuffer + inputBufferSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

bool inspectMessageBuffer(const unsigned char* inputBuffer, const int inputBufferSize, PgpInspectedMessage& out)
{
    try
    {
        std::vector<unsigned char> binary;
        if (!decodeInspectionInputToBinary(inputBuffer, inputBufferSize, binary) || binary.empty())
        {
            return false;
        }

        // Same partial-body-length splice parseAndDecryptMessage performs before parsing, for the
        // same reason: GnuPG frames anything past its own output buffer size that way, and the
        // walker below expects one contiguous body per packet. A no-op for every definite-length
        // or old-format message, which keeps using the original bytes untouched.
        std::vector<unsigned char> reassembled;
        const bool wasReassembled = reassemblePartialBodyLengths(binary, reassembled);
        const std::vector<unsigned char>& message = wasReassembled ? reassembled : binary;

        inspectPacketSequence(message, 0, message.size(), 3, out);
        return out.sawAnyPacket;
    }
    catch (...)
    {
        return false;
    }
}
// -----------------------------------------------------------------------------

std::string formatInspectionKeyIdHex(const bool haveKeyId, const unsigned char keyId[8])
{
    try
    {
        if (!haveKeyId)
        {
            return std::string(16, '?');
        }
        static const char* hexDigits = "0123456789ABCDEF";
        std::string hex;
        for (int i = 0; i < 8; ++i)
        {
            hex.push_back(hexDigits[(keyId[i] >> 4) & 0xF]);
            hex.push_back(hexDigits[keyId[i] & 0xF]);
        }
        return hex;
    }
    catch (...)
    {
        return std::string(16, '?');
    }
}
// -----------------------------------------------------------------------------

std::string formatInspectionOctetHex(const unsigned char value)
{
    try
    {
        static const char* hexDigits = "0123456789ABCDEF";
        std::string hex;
        hex.push_back(hexDigits[(value >> 4) & 0xF]);
        hex.push_back(hexDigits[value & 0xF]);
        return hex;
    }
    catch (...)
    {
        return std::string("00");
    }
}
// -----------------------------------------------------------------------------

// Shared tail of the three List* methods: hands `records` (already the exact packed fixed-stride
// byte image, NUL terminators included) to the caller under the repo's standard capacity-query
// convention -- with the one documented refinement that an EMPTY list is NO_ERROR with
// *outputBufferSize = 0 rather than BUFFER_TOO_SMALL, since no larger buffer would ever help.
int writeInspectionRecords(const std::string& records, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        const int neededSize = static_cast<int>(records.size());
        if (neededSize == 0)
        {
            *outputBufferSize = 0;
            return NO_ERROR;
        }
        if (outputBuffer == nullptr || outputBufferCapacity < neededSize)
        {
            *outputBufferSize = neededSize;
            return BUFFER_TOO_SMALL;
        }
        std::memcpy(outputBuffer, records.data(), records.size());
        *outputBufferSize = neededSize;
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

CPgpEngine::CPgpEngine(const PgpKeyAlgorithm keyAlgorithm) : impl_(new Impl())
{
    impl_->keyAlgorithm = keyAlgorithm;
}
// -----------------------------------------------------------------------------

PgpKeyAlgorithm CPgpEngine::GetKeyAlgorithm(void) const
{
    try
    {
        return impl_ ? impl_->keyAlgorithm : PGP_KEY_ALGORITHM_RSA;
    }
    catch (...)
    {
        return PGP_KEY_ALGORITHM_RSA;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::GenerateKeyPair(const char* userId, const int userIdSize, const char* password, const int passwordSize)
{
    return GenerateKeyPair(userId, userIdSize, password, passwordSize, 0);
}
// -----------------------------------------------------------------------------

int CPgpEngine::GenerateKeyPair(const char* userId, const int userIdSize, const char* password, const int passwordSize, const unsigned int expirationSeconds)
{
    try
    {
        if (!impl_ || userId == nullptr || userIdSize <= 0 || password == nullptr || passwordSize <= 0)
        {
            return INVALID_ARGUMENT;
        }

        const std::uint32_t creationTime = static_cast<std::uint32_t>(std::time(nullptr));
        std::vector<unsigned char> masterPubBody;
        std::vector<unsigned char> subkeyPubBody;
        unsigned char masterKeyId[8];
        unsigned char subkeyKeyId[8];
        std::vector<unsigned char> masterSecretBody;
        std::vector<unsigned char> subkeySecretBody;

        CryptoPP::RSA::PrivateKey rsaMasterPrivateKey;
        CryptoPP::RSA::PublicKey rsaMasterPublicKey;
        CryptoPP::RSA::PrivateKey rsaSubkeyPrivateKey;
        CryptoPP::RSA::PublicKey rsaSubkeyPublicKey;
        unsigned char edMasterPrivateKey[32];
        unsigned char edMasterPublicKey[32];
        unsigned char edSubkeyPrivateKey[32];
        unsigned char edSubkeyPublicKey[32];

        std::vector<unsigned char> certExtraSubpackets = buildKeyFlagsSubpacket(0x03);
        std::vector<unsigned char> bindExtraSubpackets = buildKeyFlagsSubpacket(0x0C);
        if (expirationSeconds > 0)
        {
            appendAll(certExtraSubpackets, buildKeyExpirationSubpacket(expirationSeconds));
            appendAll(bindExtraSubpackets, buildKeyExpirationSubpacket(expirationSeconds));
        }

        std::vector<unsigned char> certSigPacket;
        std::vector<unsigned char> bindSigPacket;

        if (impl_->keyAlgorithm == PGP_KEY_ALGORITHM_RSA)
        {
            if (impl_->rsaKeyBits != 1024 && impl_->rsaKeyBits != 2048 && impl_->rsaKeyBits != 3072 && impl_->rsaKeyBits != 4096)
            {
                return INVALID_ARGUMENT;
            }

            CryptoPP::AutoSeededRandomPool rng;

            rsaMasterPrivateKey.GenerateRandomWithKeySize(rng, static_cast<unsigned int>(impl_->rsaKeyBits));
            rsaMasterPublicKey = CryptoPP::RSA::PublicKey(rsaMasterPrivateKey);

            rsaSubkeyPrivateKey.GenerateRandomWithKeySize(rng, static_cast<unsigned int>(impl_->rsaKeyBits));
            rsaSubkeyPublicKey = CryptoPP::RSA::PublicKey(rsaSubkeyPrivateKey);

            masterPubBody = buildRsaPublicKeyPacketBody(creationTime, rsaMasterPublicKey.GetModulus(), rsaMasterPublicKey.GetPublicExponent());
            subkeyPubBody = buildRsaPublicKeyPacketBody(creationTime, rsaSubkeyPublicKey.GetModulus(), rsaSubkeyPublicKey.GetPublicExponent());
            unsigned char masterFingerprint[20];
            unsigned char subkeyFingerprint[20];
            computeFingerprintAndKeyId(masterPubBody, masterFingerprint, masterKeyId);
            computeFingerprintAndKeyId(subkeyPubBody, subkeyFingerprint, subkeyKeyId);

            std::vector<unsigned char> certDocument = buildKeyHashPrefix(masterPubBody);
            const std::string userIdStrForCert(userId, static_cast<std::size_t>(userIdSize));
            const std::vector<unsigned char> userIdBodyForCert(userIdStrForCert.begin(), userIdStrForCert.end());
            certDocument.push_back(0xB4);
            appendBigEndian32(certDocument, static_cast<std::uint32_t>(userIdBodyForCert.size()));
            appendAll(certDocument, userIdBodyForCert);
            certSigPacket = buildSignaturePacket(rsaMasterPrivateKey, 0x13, certDocument, certExtraSubpackets, masterKeyId);

            std::vector<unsigned char> bindDocument = buildKeyHashPrefix(masterPubBody);
            appendAll(bindDocument, buildKeyHashPrefix(subkeyPubBody));
            bindSigPacket = buildSignaturePacket(rsaMasterPrivateKey, 0x18, bindDocument, bindExtraSubpackets, masterKeyId);

            masterSecretBody = encryptSecretKeyMaterial(masterPubBody, buildRsaSecretKeyCleartext(rsaMasterPrivateKey), password, passwordSize);
            subkeySecretBody = encryptSecretKeyMaterial(subkeyPubBody, buildRsaSecretKeyCleartext(rsaSubkeyPrivateKey), password, passwordSize);
        }
        else
        {
            CryptoPP::AutoSeededRandomPool rng;

            CryptoPP::ed25519PrivateKey edPriv;
            edPriv.GenerateRandom(rng, CryptoPP::g_nullNameValuePairs);
            std::memcpy(edMasterPrivateKey, edPriv.GetPrivateKeyBytePtr(), 32);
            std::memcpy(edMasterPublicKey, edPriv.GetPublicKeyBytePtr(), 32);

            CryptoPP::x25519 dh;
            dh.GeneratePrivateKey(rng, edSubkeyPrivateKey);
            dh.GeneratePublicKey(rng, edSubkeyPrivateKey, edSubkeyPublicKey);

            masterPubBody = buildEd25519PublicKeyPacketBody(creationTime, edMasterPublicKey);
            subkeyPubBody = buildX25519PublicKeyPacketBody(creationTime, edSubkeyPublicKey);
            unsigned char masterFingerprint[20];
            unsigned char subkeyFingerprint[20];
            computeFingerprintAndKeyId(masterPubBody, masterFingerprint, masterKeyId);
            computeFingerprintAndKeyId(subkeyPubBody, subkeyFingerprint, subkeyKeyId);

            std::vector<unsigned char> certDocument = buildKeyHashPrefix(masterPubBody);
            const std::string userIdStrForCert(userId, static_cast<std::size_t>(userIdSize));
            const std::vector<unsigned char> userIdBodyForCert(userIdStrForCert.begin(), userIdStrForCert.end());
            certDocument.push_back(0xB4);
            appendBigEndian32(certDocument, static_cast<std::uint32_t>(userIdBodyForCert.size()));
            appendAll(certDocument, userIdBodyForCert);
            certSigPacket = buildEd25519SignaturePacket(edMasterPrivateKey, 0x13, certDocument, certExtraSubpackets, masterKeyId);

            std::vector<unsigned char> bindDocument = buildKeyHashPrefix(masterPubBody);
            appendAll(bindDocument, buildKeyHashPrefix(subkeyPubBody));
            bindSigPacket = buildEd25519SignaturePacket(edMasterPrivateKey, 0x18, bindDocument, bindExtraSubpackets, masterKeyId);

            masterSecretBody = encryptSecretKeyMaterial(masterPubBody, buildEd25519SecretKeyCleartext(edMasterPrivateKey), password, passwordSize);
            subkeySecretBody = encryptSecretKeyMaterial(subkeyPubBody, buildX25519SecretKeyCleartext(edSubkeyPrivateKey), password, passwordSize);
        }

        const std::vector<unsigned char> masterPubPacket = writePacket(PGP_TAG_PUBLIC_KEY, masterPubBody);
        const std::vector<unsigned char> subkeyPubPacket = writePacket(PGP_TAG_PUBLIC_SUBKEY, subkeyPubBody);

        const std::string userIdStr(userId, static_cast<std::size_t>(userIdSize));
        const std::vector<unsigned char> userIdBody(userIdStr.begin(), userIdStr.end());
        const std::vector<unsigned char> userIdPacket = writePacket(13, userIdBody);

        if (certSigPacket.empty() || bindSigPacket.empty() || masterSecretBody.empty() || subkeySecretBody.empty())
        {
            return UNEXPECTED_ERROR;
        }

        std::vector<unsigned char> publicKeyBlock;
        appendAll(publicKeyBlock, masterPubPacket);
        appendAll(publicKeyBlock, userIdPacket);
        appendAll(publicKeyBlock, certSigPacket);
        appendAll(publicKeyBlock, subkeyPubPacket);
        appendAll(publicKeyBlock, bindSigPacket);

        const std::vector<unsigned char> masterSecretPacket = writePacket(PGP_TAG_SECRET_KEY, masterSecretBody);
        const std::vector<unsigned char> subkeySecretPacket = writePacket(PGP_TAG_SECRET_SUBKEY, subkeySecretBody);

        std::vector<unsigned char> secretKeyBlock;
        appendAll(secretKeyBlock, masterSecretPacket);
        appendAll(secretKeyBlock, userIdPacket);
        appendAll(secretKeyBlock, certSigPacket);
        appendAll(secretKeyBlock, subkeySecretPacket);
        appendAll(secretKeyBlock, bindSigPacket);

        if (impl_->keyAlgorithm == PGP_KEY_ALGORITHM_RSA)
        {
            impl_->ownMasterPrivateKey = rsaMasterPrivateKey;
            impl_->ownMasterPublicKey = rsaMasterPublicKey;
            impl_->ownSubkeyPrivateKey = rsaSubkeyPrivateKey;
            impl_->ownSubkeyPublicKey = rsaSubkeyPublicKey;
        }
        else
        {
            std::memcpy(impl_->ownEd25519PrivateKey, edMasterPrivateKey, 32);
            std::memcpy(impl_->ownEd25519PublicKey, edMasterPublicKey, 32);
            std::memcpy(impl_->ownX25519PrivateKey, edSubkeyPrivateKey, 32);
            std::memcpy(impl_->ownX25519PublicKey, edSubkeyPublicKey, 32);
        }
        std::memcpy(impl_->ownMasterKeyId, masterKeyId, 8);
        std::memcpy(impl_->ownSubkeyKeyId, subkeyKeyId, 8);
        {
            // Recomputed from subkeyPubBody rather than threading the per-branch local fingerprint
            // variable out of the if/else above -- cheap (one SHA-1) and keeps both branches
            // symmetric.
            unsigned char subkeyFingerprintForStorage[20];
            unsigned char subkeyKeyIdRecomputed[8];
            computeFingerprintAndKeyId(subkeyPubBody, subkeyFingerprintForStorage, subkeyKeyIdRecomputed);
            std::memcpy(impl_->ownSubkeyFingerprint, subkeyFingerprintForStorage, 20);
        }
        impl_->keyCreationTime = creationTime;
        impl_->keyExpirationSeconds = expirationSeconds;
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

unsigned int CPgpEngine::GetKeyExpirationSeconds(void) const
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated)
        {
            return 0;
        }
        return static_cast<unsigned int>(impl_->keyExpirationSeconds);
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::RevokeKeyArmored(const char* password, const int passwordSize, const unsigned char reasonCode, const char* reasonText, const int reasonTextSize, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize)
{
    try
    {
        if (!impl_ || !impl_->ownKeyGenerated || password == nullptr || passwordSize <= 0 || outputBufferSize == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (!checkPasswordHash(impl_->passwordCheckHash, password, passwordSize))
        {
            return INVALID_ARGUMENT;
        }

        // Recomputed (not cached) from the same creationTime/key material GenerateKeyPair used,
        // so this byte-matches the public-key-packet body already embedded in the exported public
        // key block -- required for the revocation signature to hash the same material a keyring
        // importing it will see.
        std::vector<unsigned char> masterPubBody;
        if (impl_->keyAlgorithm == PGP_KEY_ALGORITHM_RSA)
        {
            masterPubBody = buildRsaPublicKeyPacketBody(impl_->keyCreationTime, impl_->ownMasterPublicKey.GetModulus(), impl_->ownMasterPublicKey.GetPublicExponent());
        }
        else
        {
            masterPubBody = buildEd25519PublicKeyPacketBody(impl_->keyCreationTime, impl_->ownEd25519PublicKey);
        }
        const std::vector<unsigned char> document = buildKeyHashPrefix(masterPubBody);
        const std::vector<unsigned char> reasonSubpacket = buildRevocationReasonSubpacket(reasonCode, reasonText, reasonTextSize);

        const std::vector<unsigned char> revocationSigPacket = (impl_->keyAlgorithm == PGP_KEY_ALGORITHM_RSA) ?
            buildSignaturePacket(impl_->ownMasterPrivateKey, 0x20, document, reasonSubpacket, impl_->ownMasterKeyId) :
            buildEd25519SignaturePacket(impl_->ownEd25519PrivateKey, 0x20, document, reasonSubpacket, impl_->ownMasterKeyId);
        if (revocationSigPacket.empty())
        {
            return UNEXPECTED_ERROR;
        }

        const std::string armored = armorEncode("PGP PUBLIC KEY BLOCK", revocationSigPacket);
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

int CPgpEngine::ImportPeerPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize)
{
    try
    {
        if (!impl_ || keyBlockBuffer == nullptr || keyBlockBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }

        std::vector<unsigned char> binary;
        if (!decodeKeyBlockToBinary(keyBlockBuffer, keyBlockBufferSize, binary))
        {
            return INVALID_DATA;
        }

        ParsedPeerPublicKeyBlock parsed;
        if (!parsePeerPublicKeyBlock(binary, parsed))
        {
            return INVALID_DATA;
        }

        impl_->peerMasterAlgorithm = parsed.masterAlgorithm;
        impl_->peerSubkeyAlgorithm = parsed.subkeyAlgorithm;
        if (parsed.masterAlgorithm == PGP_KEY_ALGORITHM_RSA)
        {
            impl_->peerMasterPublicKey = parsed.masterRsaKey;
        }
        else
        {
            std::memcpy(impl_->peerEd25519PublicKey, parsed.masterEd25519Key, 32);
        }
        std::memcpy(impl_->peerMasterKeyId, parsed.masterKeyId, 8);

        if (parsed.subkeyAlgorithm == PGP_KEY_ALGORITHM_RSA)
        {
            impl_->peerSubkeyPublicKey = parsed.subkeyRsaKey;
        }
        else
        {
            std::memcpy(impl_->peerX25519PublicKey, parsed.subkeyX25519Key, 32);
            std::memcpy(impl_->peerSubkeyFingerprint, parsed.subkeyFingerprint, 20);
        }
        std::memcpy(impl_->peerSubkeyKeyId, parsed.subkeyKeyId, 8);

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

int CPgpEngine::ImportAdditionalRecipientPublicKey(const unsigned char* keyBlockBuffer, const int keyBlockBufferSize)
{
    try
    {
        if (!impl_ || !impl_->peerKeyImported || keyBlockBuffer == nullptr || keyBlockBufferSize <= 0)
        {
            return INVALID_ARGUMENT;
        }

        std::vector<unsigned char> binary;
        if (!decodeKeyBlockToBinary(keyBlockBuffer, keyBlockBufferSize, binary))
        {
            return INVALID_DATA;
        }

        ParsedPeerPublicKeyBlock parsed;
        if (!parsePeerPublicKeyBlock(binary, parsed) || !parsed.haveSubkey)
        {
            return INVALID_DATA;
        }

        PgpEncryptionRecipient recipient;
        recipient.algorithm = parsed.subkeyAlgorithm;
        if (parsed.subkeyAlgorithm == PGP_KEY_ALGORITHM_RSA)
        {
            recipient.rsaPublicKey = parsed.subkeyRsaKey;
            std::memcpy(recipient.rsaKeyId, parsed.subkeyKeyId, 8);
        }
        else
        {
            std::memcpy(recipient.x25519PublicKey, parsed.subkeyX25519Key, 32);
            std::memcpy(recipient.x25519KeyId, parsed.subkeyKeyId, 8);
            std::memcpy(recipient.x25519Fingerprint, parsed.subkeyFingerprint, 20);
        }

        impl_->additionalRecipients.push_back(recipient);
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

        std::vector<PgpEncryptionRecipient> recipients;
        {
            PgpEncryptionRecipient primary;
            primary.algorithm = impl_->peerSubkeyAlgorithm;
            if (impl_->peerSubkeyAlgorithm == PGP_KEY_ALGORITHM_RSA)
            {
                primary.rsaPublicKey = impl_->peerSubkeyPublicKey;
                std::memcpy(primary.rsaKeyId, impl_->peerSubkeyKeyId, 8);
            }
            else
            {
                std::memcpy(primary.x25519PublicKey, impl_->peerX25519PublicKey, 32);
                std::memcpy(primary.x25519KeyId, impl_->peerSubkeyKeyId, 8);
                std::memcpy(primary.x25519Fingerprint, impl_->peerSubkeyFingerprint, 20);
            }
            recipients.push_back(primary);
        }
        for (std::size_t i = 0; i < impl_->additionalRecipients.size(); ++i)
        {
            recipients.push_back(impl_->additionalRecipients[i]);
        }

        std::vector<unsigned char> message;
        if (!buildEncryptedMessageMultiRecipient(recipients, inputBuffer, static_cast<std::size_t>(inputBufferSize), message))
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

        std::vector<PgpEncryptionRecipient> recipients;
        {
            PgpEncryptionRecipient primary;
            primary.algorithm = impl_->peerSubkeyAlgorithm;
            if (impl_->peerSubkeyAlgorithm == PGP_KEY_ALGORITHM_RSA)
            {
                primary.rsaPublicKey = impl_->peerSubkeyPublicKey;
                std::memcpy(primary.rsaKeyId, impl_->peerSubkeyKeyId, 8);
            }
            else
            {
                std::memcpy(primary.x25519PublicKey, impl_->peerX25519PublicKey, 32);
                std::memcpy(primary.x25519KeyId, impl_->peerSubkeyKeyId, 8);
                std::memcpy(primary.x25519Fingerprint, impl_->peerSubkeyFingerprint, 20);
            }
            recipients.push_back(primary);
        }
        for (std::size_t i = 0; i < impl_->additionalRecipients.size(); ++i)
        {
            recipients.push_back(impl_->additionalRecipients[i]);
        }

        const unsigned char* inputBytes = reinterpret_cast<const unsigned char*>(inputString);
        std::vector<unsigned char> message;
        if (!buildEncryptedMessageMultiRecipient(recipients, inputBytes, static_cast<std::size_t>(inputStringSize), message))
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
        if (!parseAndDecryptMessage(impl_->keyAlgorithm, impl_->ownSubkeyPrivateKey, impl_->ownX25519PrivateKey, impl_->ownSubkeyFingerprint, impl_->ownSubkeyKeyId, message, plaintext))
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
        if (!parseAndDecryptMessage(impl_->keyAlgorithm, impl_->ownSubkeyPrivateKey, impl_->ownX25519PrivateKey, impl_->ownSubkeyFingerprint, impl_->ownSubkeyKeyId, message, plaintext))
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
        const std::vector<unsigned char> sigPacket = (impl_->keyAlgorithm == PGP_KEY_ALGORITHM_RSA) ?
            buildSignaturePacket(impl_->ownMasterPrivateKey, 0x00, documentData, std::vector<unsigned char>(), impl_->ownMasterKeyId) :
            buildEd25519SignaturePacket(impl_->ownEd25519PrivateKey, 0x00, documentData, std::vector<unsigned char>(), impl_->ownMasterKeyId);
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
        const bool technicalOk = (impl_->peerMasterAlgorithm == PGP_KEY_ALGORITHM_RSA) ?
            verifySignaturePacket(impl_->peerMasterPublicKey, documentData, sigPacketBytes, &verified) :
            verifyEd25519SignaturePacket(impl_->peerEd25519PublicKey, documentData, sigPacketBytes, &verified);
        if (!technicalOk)
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

        const std::vector<unsigned char> sigPacket = (impl_->keyAlgorithm == PGP_KEY_ALGORITHM_RSA) ?
            buildSignaturePacket(impl_->ownMasterPrivateKey, 0x01, documentData, std::vector<unsigned char>(), impl_->ownMasterKeyId) :
            buildEd25519SignaturePacket(impl_->ownEd25519PrivateKey, 0x01, documentData, std::vector<unsigned char>(), impl_->ownMasterKeyId);
        if (sigPacket.empty())
        {
            return UNEXPECTED_ERROR;
        }

        std::string out = (impl_->keyAlgorithm == PGP_KEY_ALGORITHM_RSA) ?
            "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\n" :
            "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA512\r\n\r\n";
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
        const bool technicalOk = (impl_->peerMasterAlgorithm == PGP_KEY_ALGORITHM_RSA) ?
            verifySignaturePacket(impl_->peerMasterPublicKey, documentData, sigPacketBytes, &verified) :
            verifyEd25519SignaturePacket(impl_->peerEd25519PublicKey, documentData, sigPacketBytes, &verified);
        if (!technicalOk)
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
        std::vector<PgpEncryptionRecipient> recipients;
        {
            PgpEncryptionRecipient primary;
            primary.algorithm = impl_->peerSubkeyAlgorithm;
            if (primary.algorithm == PGP_KEY_ALGORITHM_RSA)
            {
                primary.rsaPublicKey = impl_->peerSubkeyPublicKey;
                std::memcpy(primary.rsaKeyId, impl_->peerSubkeyKeyId, 8);
            }
            else
            {
                std::memcpy(primary.x25519PublicKey, impl_->peerX25519PublicKey, 32);
                std::memcpy(primary.x25519KeyId, impl_->peerSubkeyKeyId, 8);
                std::memcpy(primary.x25519Fingerprint, impl_->peerSubkeyFingerprint, 20);
            }
            recipients.push_back(primary);
        }
        for (std::size_t i = 0; i < impl_->additionalRecipients.size(); ++i)
        {
            recipients.push_back(impl_->additionalRecipients[i]);
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

        const int status = encryptFileStreaming(recipients, rawInputHandle, fileSize, rawOutputHandle, onProgress, progressUserData);
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

int CPgpEngine::EncryptFileCompressed(const char* inputFilePath, const char* outputFilePath, const PgpFileCompressionAlgorithm compressionAlgorithm, ProgressCallback onProgress, void* progressUserData)
{
    try
    {
        if (!impl_ || !impl_->peerKeyImported || inputFilePath == nullptr || outputFilePath == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        if (compressionAlgorithm != PGP_FILE_COMPRESSION_ALGORITHM_ZIP && compressionAlgorithm != PGP_FILE_COMPRESSION_ALGORITHM_ZLIB)
        {
            return INVALID_ARGUMENT;
        }
        std::vector<PgpEncryptionRecipient> recipients;
        {
            PgpEncryptionRecipient primary;
            primary.algorithm = impl_->peerSubkeyAlgorithm;
            if (primary.algorithm == PGP_KEY_ALGORITHM_RSA)
            {
                primary.rsaPublicKey = impl_->peerSubkeyPublicKey;
                std::memcpy(primary.rsaKeyId, impl_->peerSubkeyKeyId, 8);
            }
            else
            {
                std::memcpy(primary.x25519PublicKey, impl_->peerX25519PublicKey, 32);
                std::memcpy(primary.x25519KeyId, impl_->peerSubkeyKeyId, 8);
                std::memcpy(primary.x25519Fingerprint, impl_->peerSubkeyFingerprint, 20);
            }
            recipients.push_back(primary);
        }
        for (std::size_t i = 0; i < impl_->additionalRecipients.size(); ++i)
        {
            recipients.push_back(impl_->additionalRecipients[i]);
        }

        std::wstring wideInputPath;
        std::wstring wideOutputPath;
        if (!convertUtf8PathToWide(inputFilePath, wideInputPath) || !convertUtf8PathToWide(outputFilePath, wideOutputPath))
        {
            return INVALID_ARGUMENT;
        }
        const std::wstring wideTempPath = wideOutputPath + L".pgpztmp";

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
        const unsigned char compressionAlgorithmOctet = static_cast<unsigned char>(compressionAlgorithm);

        unsigned long long compressedSize = 0;
        const int compressStatus = compressLiteralToTempFile(rawInputHandle, fileSize, compressionAlgorithmOctet, wideTempPath, onProgress, progressUserData, compressedSize);
        if (compressStatus != NO_ERROR)
        {
            DeleteFileW(wideTempPath.c_str());
            return compressStatus;
        }

        const HANDLE rawOutputHandle = CreateFileW(wideOutputPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (rawOutputHandle == INVALID_HANDLE_VALUE)
        {
            DeleteFileW(wideTempPath.c_str());
            return FILE_IO_ERROR;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> outputHandle(rawOutputHandle, &CloseHandle);

        const int status = encryptFileStreamingCompressed(recipients, wideTempPath, compressedSize, compressionAlgorithmOctet, rawOutputHandle, onProgress, progressUserData);
        DeleteFileW(wideTempPath.c_str());
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

        const DecryptFileHeader header = parseEncryptedFileHeader(rawInputHandle, impl_->keyAlgorithm, impl_->ownSubkeyPrivateKey, impl_->ownX25519PrivateKey, impl_->ownSubkeyFingerprint, impl_->ownSubkeyKeyId);
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
                                                     header.seipPartial, header.seipChunkRemaining, header.seipFinalChunk,
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
        const int status = impl_->keyAlgorithm == PGP_KEY_ALGORITHM_RSA
            ? signFileStreaming(impl_->ownMasterPrivateKey, rawInputHandle, fileSize, impl_->ownMasterKeyId, onProgress, progressUserData, signaturePacket)
            : signEd25519FileStreaming(impl_->ownEd25519PrivateKey, rawInputHandle, fileSize, impl_->ownMasterKeyId, onProgress, progressUserData, signaturePacket);
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

        return impl_->peerMasterAlgorithm == PGP_KEY_ALGORITHM_RSA
            ? verifyFileStreaming(impl_->peerMasterPublicKey, rawInputHandle, fileSize, signaturePacketBytes, isValid, onProgress, progressUserData)
            : verifyEd25519FileStreaming(impl_->peerEd25519PublicKey, rawInputHandle, fileSize, signaturePacketBytes, isValid, onProgress, progressUserData);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::IsPublicKeyEncrypted(const unsigned char* inputBuffer, const int inputBufferSize, bool* isPublicKeyEncrypted) const
{
    try
    {
        if (inputBuffer == nullptr || inputBufferSize <= 0 || isPublicKeyEncrypted == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        PgpInspectedMessage inspected;
        if (!inspectMessageBuffer(inputBuffer, inputBufferSize, inspected))
        {
            return INVALID_DATA;
        }
        *isPublicKeyEncrypted = inspected.hasPkesk;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::IsPasswordEncrypted(const unsigned char* inputBuffer, const int inputBufferSize, bool* isPasswordEncrypted) const
{
    try
    {
        if (inputBuffer == nullptr || inputBufferSize <= 0 || isPasswordEncrypted == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        PgpInspectedMessage inspected;
        if (!inspectMessageBuffer(inputBuffer, inputBufferSize, inspected))
        {
            return INVALID_DATA;
        }
        *isPasswordEncrypted = inspected.hasSkesk;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::IsIntegrityProtected(const unsigned char* inputBuffer, const int inputBufferSize, bool* isIntegrityProtected) const
{
    try
    {
        if (inputBuffer == nullptr || inputBufferSize <= 0 || isIntegrityProtected == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        PgpInspectedMessage inspected;
        if (!inspectMessageBuffer(inputBuffer, inputBufferSize, inspected))
        {
            return INVALID_DATA;
        }
        *isIntegrityProtected = inspected.hasIntegrityProtectedData;
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::GetCompression(const unsigned char* inputBuffer, const int inputBufferSize, int* compressionAlgorithm) const
{
    try
    {
        if (inputBuffer == nullptr || inputBufferSize <= 0 || compressionAlgorithm == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        PgpInspectedMessage inspected;
        if (!inspectMessageBuffer(inputBuffer, inputBufferSize, inspected))
        {
            return INVALID_DATA;
        }
        if (inspected.hasCompressedData)
        {
            *compressionAlgorithm = static_cast<int>(inspected.compressionAlgorithm);
        }
        else if (inspected.hasIntegrityProtectedData || inspected.hasUnprotectedEncryptedData)
        {
            // Encrypted, and no Compressed Data packet visible OUTSIDE the ciphertext -- which is
            // exactly the case where nobody can answer the question without the decryption key,
            // so say so instead of reporting a confident "not compressed".
            *compressionAlgorithm = PGP_COMPRESSION_UNKNOWN_NEEDS_DECRYPTION;
        }
        else
        {
            *compressionAlgorithm = PGP_COMPRESSION_NOT_PRESENT;
        }
        return NO_ERROR;
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::ListEncryptionKeyIds(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize, int* keyIdCount) const
{
    try
    {
        if (inputBuffer == nullptr || inputBufferSize <= 0 || outputBufferSize == nullptr || keyIdCount == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        PgpInspectedMessage inspected;
        if (!inspectMessageBuffer(inputBuffer, inputBufferSize, inspected))
        {
            return INVALID_DATA;
        }

        std::string records;
        for (std::size_t i = 0; i < inspected.recipientKeyIds.size(); ++i)
        {
            records += formatInspectionKeyIdHex(true, &inspected.recipientKeyIds[i][0]);
            records.push_back('\0');
        }
        *keyIdCount = static_cast<int>(inspected.recipientKeyIds.size());
        return writeInspectionRecords(records, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::ListSigningKeyIds(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize, int* keyIdCount) const
{
    try
    {
        if (inputBuffer == nullptr || inputBufferSize <= 0 || outputBufferSize == nullptr || keyIdCount == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        PgpInspectedMessage inspected;
        if (!inspectMessageBuffer(inputBuffer, inputBufferSize, inspected))
        {
            return INVALID_DATA;
        }

        std::string records;
        for (std::size_t i = 0; i < inspected.signatures.size(); ++i)
        {
            records += formatInspectionKeyIdHex(inspected.signatures[i].haveIssuerKeyId, inspected.signatures[i].issuerKeyId);
            records.push_back('\0');
        }
        *keyIdCount = static_cast<int>(inspected.signatures.size());
        return writeInspectionRecords(records, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

int CPgpEngine::ListSignatures(const unsigned char* inputBuffer, const int inputBufferSize, const int outputBufferCapacity, char* outputBuffer, int* outputBufferSize, int* signatureCount) const
{
    try
    {
        if (inputBuffer == nullptr || inputBufferSize <= 0 || outputBufferSize == nullptr || signatureCount == nullptr)
        {
            return INVALID_ARGUMENT;
        }
        PgpInspectedMessage inspected;
        if (!inspectMessageBuffer(inputBuffer, inputBufferSize, inspected))
        {
            return INVALID_DATA;
        }

        std::string records;
        for (std::size_t i = 0; i < inspected.signatures.size(); ++i)
        {
            records += formatInspectionKeyIdHex(inspected.signatures[i].haveIssuerKeyId, inspected.signatures[i].issuerKeyId);
            records.push_back(':');
            records += formatInspectionOctetHex(inspected.signatures[i].signatureType);
            records.push_back(':');
            records += formatInspectionOctetHex(inspected.signatures[i].hashAlgorithm);
            records.push_back('\0');
        }
        *signatureCount = static_cast<int>(inspected.signatures.size());
        return writeInspectionRecords(records, outputBufferCapacity, outputBuffer, outputBufferSize);
    }
    catch (...)
    {
        return UNEXPECTED_ERROR;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

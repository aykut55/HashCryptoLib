#ifndef CRYPTOAPI_UTILS_H
#define CRYPTOAPI_UTILS_H

namespace CryptoApiNS
{

// Block-cipher padding schemes for CUtils::Pad/Unpad. PKCS5 is byte-identical to PKCS7 (PKCS5 was
// originally defined only for 8-byte blocks; PKCS7 generalized the same algorithm to any block
// size up to 255 bytes -- libraries commonly expose both names for the same behavior).
enum PaddingScheme
{
    PADDING_PKCS7     = 0,
    PADDING_PKCS5     = 1,
    PADDING_ANSI_X923 = 2,
    PADDING_ISO_10126 = 3,
    PADDING_ISO_97971 = 4,
    PADDING_ZERO      = 5,
    PADDING_NONE      = 6
};

class CUtils
{
public:
    virtual ~CUtils();
             CUtils();

    static const char* FormatBuildDate(void);

    // Encodes inputBuffer as hexadecimal text (2 chars per byte, no separators). upperCase selects
    // 'A'-'F' digits when true, 'a'-'f' when false. Follows the BUFFER_TOO_SMALL capacity-query
    // convention: pass outputBufferCapacity=0/outputBuffer=nullptr to get the required size.
    static int HexEncode( const unsigned char* inputBuffer, const int inputBufferSize,
                          const bool upperCase,
                          const int outputBufferCapacity,
                          char* outputBuffer,
                          int* outputBufferSize);

    // Decodes hexadecimal text (2 chars per byte, upper/lower/mixed case all accepted, no
    // separators) back to raw bytes. inputStringSize must be even; odd length or non-hex
    // characters return INVALID_ARGUMENT/INVALID_DATA. Same BUFFER_TOO_SMALL convention.
    static int HexDecode( const char* inputString, const int inputStringSize,
                          const int outputBufferCapacity,
                          unsigned char* outputBuffer,
                          int* outputBufferSize);

    // Encodes inputBuffer as standard Base64 text (RFC 4648, '+'/'/' alphabet, '=' padding).
    // Same BUFFER_TOO_SMALL convention.
    static int Base64Encode( const unsigned char* inputBuffer, const int inputBufferSize,
                             const int outputBufferCapacity,
                             char* outputBuffer,
                             int* outputBufferSize);

    // Decodes standard Base64 text (RFC 4648) back to raw bytes. inputStringSize must be a
    // multiple of 4; malformed input returns INVALID_ARGUMENT/INVALID_DATA. Same BUFFER_TOO_SMALL
    // convention.
    static int Base64Decode( const char* inputString, const int inputStringSize,
                             const int outputBufferCapacity,
                             unsigned char* outputBuffer,
                             int* outputBufferSize);

    // Pads inputBuffer to a multiple of blockSize per scheme (1-255; block ciphers only ever use
    // small block sizes, so the 1-byte pad-length encoding used by PKCS7/PKCS5/AnsiX923/Iso10126
    // is never a real limit). PADDING_NONE requires inputBufferSize already be a multiple of
    // blockSize (returns INVALID_ARGUMENT otherwise) and copies the input through unchanged.
    // PADDING_ZERO adds no padding at all when already aligned (ambiguous with genuine trailing
    // zero bytes in the plaintext -- documented caveat, not a bug). PADDING_ISO_10126's filler
    // bytes use a non-cryptographic RNG since they are discarded on Unpad and carry no security
    // value. Same BUFFER_TOO_SMALL capacity-query convention as the rest of this class.
    static int Pad( const PaddingScheme scheme, const unsigned int blockSize,
                    const unsigned char* inputBuffer, const int inputBufferSize,
                    const int outputBufferCapacity,
                    unsigned char* outputBuffer,
                    int* outputBufferSize);

    // Reverses Pad. inputBufferSize must already be a non-zero multiple of blockSize (INVALID_
    // ARGUMENT otherwise); malformed padding (bad pad-length byte, wrong marker byte, inconsistent
    // pad bytes) returns INVALID_DATA. PADDING_ZERO cannot distinguish genuine trailing zero bytes
    // from padding and will strip them regardless -- same caveat as Pad. Computing the unpadded
    // size requires validating the padding structure, so that validation also runs during the
    // capacity-query call (outputBuffer == nullptr), not only on the real call.
    static int Unpad( const PaddingScheme scheme, const unsigned int blockSize,
                      const unsigned char* inputBuffer, const int inputBufferSize,
                      const int outputBufferCapacity,
                      unsigned char* outputBuffer,
                      int* outputBufferSize);

protected:

private:

};

} // namespace CryptoApiNS

#endif

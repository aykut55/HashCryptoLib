#ifndef CRYPTOAPI_UTILS_H
#define CRYPTOAPI_UTILS_H

namespace CryptoApiNS
{

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

protected:

private:

};

} // namespace CryptoApiNS

#endif

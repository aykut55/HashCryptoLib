#ifndef CRYPTOAPI_DEFINITIONS_H
#define CRYPTOAPI_DEFINITIONS_H

namespace CryptoApiNS
{

enum ErrorCode
{
    NO_ERROR = 0,
    NOT_IMPLEMENTED = 1,
    UNEXPECTED_ERROR = 2,
    BUFFER_TOO_SMALL = 3,
    INVALID_ARGUMENT = 4,
    FILE_IO_ERROR = 5,
    INVALID_DATA = 6,
    OPERATION_CANCELLED = 7
};

// Invoked after each processed chunk during EncryptFile/DecryptFile/EncryptBuffer/DecryptBuffer/
// EncryptString/DecryptString. currentByte and totalByte are measured in bytes of the operation's
// source data; percentage is currentByte/totalByte * 100. Return true to continue the operation,
// or false to abort it at the next chunk boundary with OPERATION_CANCELLED.
typedef bool (__cdecl *ProgressCallback)( const unsigned long long currentByte,
                                          const unsigned long long totalByte,
                                          const double percentage,
                                          void* userData);

} // namespace CryptoApiNS

#endif

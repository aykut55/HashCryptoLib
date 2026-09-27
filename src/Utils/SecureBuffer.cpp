#include "SecureBuffer.h"

#include <Windows.h>

#include <cstring>

namespace CryptoApiNS
{

CSecureBuffer::~CSecureBuffer()
{
    try
    {
        Clear();
    }
    catch (...)
    {
    }
}
// -----------------------------------------------------------------------------

CSecureBuffer::CSecureBuffer(const char* data, const int size)
    : buffer_(nullptr)
    , size_(0)
{
    try
    {
        const int copySize = (data != nullptr && size > 0) ? size : 0;
        buffer_ = new unsigned char[copySize + 1];
        if (copySize > 0)
        {
            std::memcpy(buffer_, data, copySize);
        }
        buffer_[copySize] = 0;
        size_ = copySize;
    }
    catch (...)
    {
    }
}
// -----------------------------------------------------------------------------

void CSecureBuffer::Clear(void)
{
    try
    {
        if (buffer_ != nullptr)
        {
            SecureZeroMemory(buffer_, static_cast<SIZE_T>(size_) + 1);
            delete[] buffer_;
            buffer_ = nullptr;
        }
        size_ = 0;
    }
    catch (...)
    {
    }
}
// -----------------------------------------------------------------------------

const char* CSecureBuffer::Data(void) const
{
    try
    {
        return reinterpret_cast<const char*>(buffer_);
    }
    catch (...)
    {
        return nullptr;
    }
}
// -----------------------------------------------------------------------------

int CSecureBuffer::Size(void) const
{
    try
    {
        return size_;
    }
    catch (...)
    {
        return 0;
    }
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

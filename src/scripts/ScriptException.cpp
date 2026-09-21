#include "ScriptException.h"

namespace CryptoApiNS
{

CScriptException::~CScriptException()
{
}
// -----------------------------------------------------------------------------

CScriptException::CScriptException(const ErrorCode errorCode, const std::string& message) : std::runtime_error(message), errorCode_(errorCode)
{
}
// -----------------------------------------------------------------------------

ErrorCode CScriptException::GetErrorCode(void) const
{
    return errorCode_;
}
// -----------------------------------------------------------------------------

} // namespace CryptoApiNS

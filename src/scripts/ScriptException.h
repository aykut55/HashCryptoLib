#ifndef CRYPTOAPI_SCRIPTS_SCRIPT_EXCEPTION_H
#define CRYPTOAPI_SCRIPTS_SCRIPT_EXCEPTION_H

#include "Definitions/Definitions.h"

#include <stdexcept>
#include <string>

// Deliberate, scoped departure from Rules.md's "exception never crosses a boundary" convention:
// that rule protects the DLL boundary (CCryptoApi/CPgpEngine/CPgpEngineWrapper), which this file
// does not touch. Everything under src/scripts/ instead converts ErrorCode into a thrown
// CScriptException at the script-facing facade boundary, because every scripting binding library
// this SDK targets (sol2/pybind11/ChaiScript) natively turns a thrown C++ exception into a
// script-land catchable error, which is the idiom script authors already expect.
namespace CryptoApiNS
{

class CScriptException : public std::runtime_error
{
public:
    virtual ~CScriptException();
             CScriptException(const ErrorCode errorCode, const std::string& message);

    ErrorCode GetErrorCode(void) const;

protected:

private:

    ErrorCode errorCode_;

};

} // namespace CryptoApiNS

#endif

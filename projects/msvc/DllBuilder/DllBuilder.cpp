// DllBuilder.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "DllBuilder.h"


// This is an example of an exported variable
DLLBUILDER_API int nDllBuilder=0;

// This is an example of an exported function.
DLLBUILDER_API int fnDllBuilder(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CDllBuilder::CDllBuilder()
{
    return;
}

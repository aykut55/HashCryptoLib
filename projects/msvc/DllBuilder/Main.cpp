#pragma once

// Windows Header Files
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Main.cpp : Defines the entry point for the DLL application.
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        // Code to run when the DLL is loaded by a process
        case DLL_PROCESS_ATTACH:
            break;

        // Code to run when a new thread is created within the process
        case DLL_THREAD_ATTACH:
            break;

        // Code to run when a thread exits cleanly
        case DLL_THREAD_DETACH:
            break;

        // Code to run when the DLL is unloaded from the process
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}

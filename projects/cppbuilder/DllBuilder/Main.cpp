// DLL entry point only; shared SDK implementation will live in src.
// The empty entry point needs no Windows SDK declarations.
extern "C" int __stdcall DllEntryPoint(void*, unsigned long, void*)
{
    return 1;
}

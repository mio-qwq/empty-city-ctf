#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
#pragma comment(linker, "/ENTRY:main")
#pragma comment(linker, "/NODEFAULTLIB")
#pragma section(".CRT$XLA", read)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
#pragma section(".rdata$T", read)

#pragma data_seg(".tls")
char tls_start = 0;
#pragma data_seg(".tls$ZZZ")
char tls_end = 0;
#pragma data_seg()
unsigned long tls_index = 0;

static void NTAPI probe(PVOID module, DWORD reason, PVOID reserved)
{
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        ExitProcess(7);
}

__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK xl_a = 0;
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK xl_b = probe;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK xl_z = 0;

__declspec(allocate(".rdata$T")) const IMAGE_TLS_DIRECTORY32 _tls_used = {
    (ULONG)(ULONG_PTR)&tls_start,
    (ULONG)(ULONG_PTR)&tls_end,
    (ULONG)(ULONG_PTR)&tls_index,
    (ULONG)(ULONG_PTR)(&xl_a + 1),
    0,
    0
};

#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_xl_b")

int main(void)
{
    return 0;
}

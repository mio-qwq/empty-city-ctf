#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>

#if !defined(_M_IX86)
#error Use the x86 MSVC compiler.
#endif

#pragma comment(linker, "/ENTRY:main")
#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/EXPORT:main=_main")
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:___xl_b")

/* Refer directly to IAT cells; do not create .text import thunks. */
extern PVOID iat_CreateFileW, iat_ReadFile, iat_CloseHandle;
extern PVOID iat_MessageBoxW, iat_ExitProcess, iat_AddVEH;
#pragma comment(linker, "/alternatename:_iat_CreateFileW=__imp__CreateFileW@28")
#pragma comment(linker, "/alternatename:_iat_ReadFile=__imp__ReadFile@20")
#pragma comment(linker, "/alternatename:_iat_CloseHandle=__imp__CloseHandle@4")
#pragma comment(linker, "/alternatename:_iat_MessageBoxW=__imp__MessageBoxW@16")
#pragma comment(linker, "/alternatename:_iat_ExitProcess=__imp__ExitProcess@4")
#pragma comment(linker, "/alternatename:_iat_AddVEH=__imp__AddVectoredExceptionHandler@8")

typedef struct {
    unsigned char code[0x1000];
    PVOID *iat[6];
} CITY_BLOB;

/* NASM produces bytes at build time; the PE contains only numeric data. */
static CITY_BLOB city = {
    {
#include "blob_bytes.inc"
    },
    { &iat_CreateFileW, &iat_ReadFile, &iat_CloseHandle,
      &iat_MessageBoxW, &iat_ExitProcess, &iat_AddVEH }
};
C_ASSERT(sizeof(PVOID) == 4);
C_ASSERT(offsetof(CITY_BLOB, iat) == 0x1000);
C_ASSERT(offsetof(CONTEXT, Eip) == 0xB8);

#pragma data_seg(".tls")
char _tls_start = 0;
#pragma data_seg(".tls$ZZZ")
char _tls_end = 0;
#pragma data_seg()
unsigned long _tls_index = 0;

#pragma section(".CRT$XLA", read)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
#pragma section(".rdata$T", read)
__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK __xl_a = 0;
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK __xl_b =
    (PIMAGE_TLS_CALLBACK)city.code;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK __xl_z = 0;
__declspec(allocate(".rdata$T")) const IMAGE_TLS_DIRECTORY32 _tls_used = {
    (ULONG)(ULONG_PTR)&_tls_start,
    (ULONG)(ULONG_PTR)&_tls_end,
    (ULONG)(ULONG_PTR)&_tls_index,
    (ULONG)(ULONG_PTR)(&__xl_a + 1), 0, 0
};

/* The only ordinary function in the image. */
int main(void)
{
    return 0;
}

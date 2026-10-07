#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Temporary x86 control sample: ordinary C VEH code, manual TLS directory. */
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
#pragma comment(linker, "/ENTRY:main")
#pragma comment(linker, "/NODEFAULTLIB")

#pragma section(".CRT$XLA", read)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
#pragma section(".rdata$T", read)
#pragma section(".blob", read, write)

#pragma data_seg(".tls")
char _tls_start = 0;
#pragma data_seg(".tls$ZZZ")
char _tls_end = 0;
#pragma data_seg()
unsigned long _tls_index = 0;

static void NTAPI tls_callback(PVOID, DWORD, PVOID);
static LONG WINAPI veh(PEXCEPTION_POINTERS);

typedef struct _BLOB_PROBE {
    unsigned char code[0x10];
    PVOID exit_process;
} BLOB_PROBE;

__declspec(allocate(".blob")) static BLOB_PROBE blob_probe = {
    {
        0xE8, 0x00, 0x00, 0x00, 0x00, /* call next */
        0x5E,                         /* pop esi */
        0x6A, 0x19,                   /* ExitProcess(25) */
        0x8B, 0x86, 0x0B, 0x00, 0x00, 0x00,
        0xFF, 0xD0                    /* call [esi + 0Bh] */
    },
    (PVOID)(ULONG_PTR)ExitProcess
};

__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK __xl_a = 0;
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK __xl_b = tls_callback;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK __xl_z = 0;

__declspec(allocate(".rdata$T")) const IMAGE_TLS_DIRECTORY32 _tls_used = {
    (ULONG)(ULONG_PTR)&_tls_start,
    (ULONG)(ULONG_PTR)&_tls_end,
    (ULONG)(ULONG_PTR)&_tls_index,
    (ULONG)(ULONG_PTR)(&__xl_a + 1),
    0,
    0
};

#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:___xl_b")

static LONG WINAPI veh(PEXCEPTION_POINTERS info)
{
    if (info != NULL && info->ExceptionRecord != NULL &&
        info->ContextRecord != NULL &&
        info->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        info->ContextRecord->Eip = (DWORD)(ULONG_PTR)blob_probe.code;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved)
{
    volatile int numerator = 1;
    volatile int denominator = 0;
    volatile int result;
    (void)module;
    (void)reserved;

    if (reason != DLL_PROCESS_ATTACH)
        return;
    if (AddVectoredExceptionHandler(1, veh) == NULL)
        ExitProcess(17);
    result = numerator / denominator;
    (void)result;
    ExitProcess(18);
}

int main(void)
{
    return 0;
}

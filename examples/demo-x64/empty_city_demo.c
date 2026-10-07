#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/*
   Empty City / Kong Cheng Ji - numeric data blob variant.

   The interesting payload is a global byte array in .data.  It is not a C
   function.  The TLS callback makes that page executable, installs a VEH,
   causes an integer divide-by-zero, and the VEH redirects CONTEXT.Rip to the
   byte array.

   This is a Windows x64 teaching sample and intentionally has unsafe linker
   flags.  It is not production code.
*/

#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
#pragma comment(linker, "/ENTRY:main")
#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/EXPORT:main")

#pragma section(".tls$AAA", read, write)
#pragma section(".tls$ZZZ", read, write)
#pragma section(".CRT$XLA", read)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
#pragma section(".rdata$T", read)

__declspec(allocate(".tls$AAA")) char _tls_start = 0;
__declspec(allocate(".tls$ZZZ")) char _tls_end = 0;
unsigned long _tls_index = 0;

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved);
static LONG WINAPI veh_handler(PEXCEPTION_POINTERS info);
static DWORD __declspec(noinline) opaque_mix(DWORD value);
static void __declspec(noinline) trigger_divide_by_zero(void);

/* The linker concatenates the $-ordered pieces into the TLS callback array. */
__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK __xl_a = 0;
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK __xl_b = tls_callback;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK __xl_z = 0;

/* Normally supplied by the CRT; here it is supplied manually. */
__declspec(allocate(".rdata$T")) const IMAGE_TLS_DIRECTORY64 _tls_used = {
    (ULONGLONG)(ULONG_PTR)&_tls_start,
    (ULONGLONG)(ULONG_PTR)&_tls_end,
    (ULONGLONG)(ULONG_PTR)&_tls_index,
    (ULONGLONG)(ULONG_PTR)(&__xl_a + 1),
    0,
    0
};

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:__xl_b")
#else
#error This sample is intentionally x64-only.
#endif

/*
   x64 machine-code payload represented only as numeric global data.

   The four 64-bit immediates are patched at runtime with the addresses of
   kernel32 functions.  The final 35 bytes are the message string.
*/
#pragma section(".data", read, write)
__declspec(allocate(".data")) static unsigned char payload[] = {
    0x48, 0x83, 0xEC, 0x58,                         /* sub rsp, 58h        */
    0xB9, 0xF5, 0xFF, 0xFF, 0xFF,                   /* mov ecx, -11        */
    0x48, 0xB8,                                     /* mov rax, imm64      */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* GetStdHandle       */
    0xFF, 0xD0,                                     /* call rax             */
    0x48, 0x89, 0x44, 0x24, 0x30,                   /* mov [rsp+30h], rax  */
    0x48, 0x8B, 0x4C, 0x24, 0x30,                   /* mov rcx,[rsp+30h]   */
    0x48, 0xBA,                                     /* mov rdx, imm64      */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* message             */
    0x41, 0xB8, 0x23, 0x00, 0x00, 0x00,             /* mov r8d, 23h        */
    0x4C, 0x8D, 0x4C, 0x24, 0x38,                   /* lea r9,[rsp+38h]    */
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, /* overlapped=NULL */
    0x48, 0xB8,                                     /* mov rax, imm64      */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* WriteFile          */
    0xFF, 0xD0,                                     /* call rax             */
    0x33, 0xC9,                                     /* xor ecx, ecx        */
    0x48, 0xB8,                                     /* mov rax, imm64      */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ExitProcess         */
    0xFF, 0xD0,                                     /* call rax             */
    0xCC,                                           /* int 3 if it returns */
    0x48, 0x83, 0xC4, 0x58,                         /* add rsp, 58h        */
    0xC3,                                           /* ret                  */
    'H','e','l','l','o',' ','w','o','r','l','d',' ',
    'f','r','o','m',' ','n','u','m','e','r','i','c',' ',
    'T','L','S',' ','b','l','o','b','!','\r','\n'
};

enum {
    PAYLOAD_GETSTD_IMM = 11,
    PAYLOAD_MESSAGE_IMM = 33,
    PAYLOAD_WRITEFILE_IMM = 63,
    PAYLOAD_EXITPROCESS_IMM = 77,
    PAYLOAD_MESSAGE = 93,
    PAYLOAD_MESSAGE_LENGTH = 35
};

static volatile DWORD g_junk_sink = 0;
static volatile int g_div_result = 0;

static void patch_u64(unsigned char *where, ULONG_PTR value)
{
    unsigned int i;
    for (i = 0; i != 8; ++i)
        where[i] = (unsigned char)(value >> (i * 8));
}

static DWORD __declspec(noinline) opaque_mix(DWORD value)
{
    volatile DWORD x = value ^ 0x13579BDFu;
    x = (x << 7) | (x >> 25);
    x += 0x9E3779B9u;
    x ^= x >> 11;
    x *= 33u;
    return x ^ (x >> 17);
}

static void __declspec(noinline) trigger_divide_by_zero(void)
{
    volatile int numerator = 1;
    volatile int denominator = 0;
    g_div_result = numerator / denominator;
}

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS info)
{
    if (info != NULL &&
        info->ExceptionRecord != NULL &&
        info->ContextRecord != NULL &&
        info->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        /* Normalize the synthetic x64 function-entry stack alignment. */
        if ((info->ContextRecord->Rsp & 0x0Fu) == 0)
            info->ContextRecord->Rsp -= 8;

        info->ContextRecord->Rip = (DWORD64)(ULONG_PTR)payload;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved)
{
    DWORD old_protect = 0;
    (void)module;

    if (reason != DLL_PROCESS_ATTACH)
        return;

    /* Harmless opaque arithmetic kept in the TLS path as visual noise. */
    g_junk_sink ^= opaque_mix((DWORD)(ULONG_PTR)reserved ^ 0xA5A5A5A5u);
    if ((g_junk_sink & 0xFFFF0000u) == 0xDEAD0000u)
        g_junk_sink ^= opaque_mix(0xCAFEBABEu);

    patch_u64(payload + PAYLOAD_GETSTD_IMM,
              (ULONG_PTR)GetStdHandle);
    patch_u64(payload + PAYLOAD_MESSAGE_IMM,
              (ULONG_PTR)(payload + PAYLOAD_MESSAGE));
    patch_u64(payload + PAYLOAD_WRITEFILE_IMM,
              (ULONG_PTR)WriteFile);
    patch_u64(payload + PAYLOAD_EXITPROCESS_IMM,
              (ULONG_PTR)ExitProcess);

    /* DEP/NX is not assumed to be disabled by the host policy. */
    if (!VirtualProtect(payload, sizeof(payload), PAGE_EXECUTE_READWRITE,
                        &old_protect))
        ExitProcess(2);

    if (AddVectoredExceptionHandler(1, veh_handler) == NULL)
        ExitProcess(3);

    trigger_divide_by_zero();

    /* Normally unreachable because the VEH redirects execution first. */
    ExitProcess(4);
}

/* Apparent entry point / decoy.  The TLS path exits before reaching it. */
int main(void)
{
    return 0;
}

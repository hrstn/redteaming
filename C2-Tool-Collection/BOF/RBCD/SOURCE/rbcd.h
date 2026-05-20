#pragma once

#include <windows.h>
#include <activeds.h>

/* ── MSVCRT ──────────────────────────────────────────────────────── */
WINBASEAPI errno_t  __cdecl MSVCRT$wcscpy_s(wchar_t *dst, rsize_t dstSize, const wchar_t *src);
WINBASEAPI errno_t  __cdecl MSVCRT$wcscat_s(wchar_t *dst, size_t dstSize, const wchar_t *src);
WINBASEAPI size_t   __cdecl MSVCRT$wcslen(const wchar_t *str);
WINBASEAPI void     __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcschr(const wchar_t *str, wchar_t c);
WINBASEAPI errno_t  __cdecl MSVCRT$wcsncpy_s(wchar_t *dst, rsize_t dstSize, const wchar_t *src, rsize_t count);

/* ── KERNEL32 ─────────────────────────────────────────────────────── */
WINBASEAPI DWORD   WINAPI KERNEL32$FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments);
WINBASEAPI HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID);

/* ── USER32 ──────────────────────────────────────────────────────── */
WINBASEAPI LPWSTR  WINAPI USER32$CharLowerW(LPWSTR lpsz);
WINBASEAPI LPWSTR  WINAPI USER32$CharUpperW(LPWSTR lpsz);

/* ── OLE32 ───────────────────────────────────────────────────────── */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);

/* ── OLEAUT32 ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);

/* ── NETAPI32 ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR ComputerName, LPCWSTR DomainName, GUID *DomainGuid, LPCWSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFOW *DomainControllerInfo);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

/* ── ADVAPI32 ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(
    LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision,
    PSECURITY_DESCRIPTOR *SecurityDescriptor, PULONG SecurityDescriptorSize);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID Sid, LPWSTR *StringSid);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(
    PSECURITY_DESCRIPTOR SecurityDescriptor, DWORD RequestedStringSDRevision,
    SECURITY_INFORMATION SecurityInformation,
    LPWSTR *StringSecurityDescriptor, PULONG StringSecurityDescriptorLen);

/* ── ACTIVEDS (dynamically loaded from Activeds.dll) ─────────────── */
typedef HRESULT (WINAPI *_ADsOpenObject)(
    LPCWSTR lpszPathName, LPCWSTR lpszUserName, LPCWSTR lpszPassword,
    DWORD dwReserved, REFIID riid, void **ppObject);

typedef VOID (WINAPI *_FreeADsMem)(LPVOID pMem);

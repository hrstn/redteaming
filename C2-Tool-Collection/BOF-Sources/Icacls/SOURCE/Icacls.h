#pragma once

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

/* ---- API declarations (MODULE$ dynamic imports, resolved by the AdaptixC2
 *      loader as __imp_<MODULE>$<func>; anything not __imp_-prefixed is left
 *      unresolved, so declare EVERY external this way and use MSVCRT$ for libc. */

/* ADVAPI32 — security descriptor / ACL / SID resolution */
WINADVAPI DWORD WINAPI ADVAPI32$GetNamedSecurityInfoW(
    LPCWSTR pObjectName, SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo, PSID *ppsidOwner, PSID *ppsidGroup,
    PACL *ppDacl, PACL *ppSacl, PSECURITY_DESCRIPTOR *ppSecurityDescriptor);
WINADVAPI BOOL WINAPI ADVAPI32$GetAclInformation(
    PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength,
    ACL_INFORMATION_CLASS dwAclInformationClass);
WINADVAPI BOOL WINAPI ADVAPI32$GetAce(PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);
WINADVAPI BOOL WINAPI ADVAPI32$LookupAccountSidW(
    LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName,
    LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse);
WINADVAPI BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID Sid, LPWSTR *StringSid);
WINADVAPI BOOL WINAPI ADVAPI32$IsValidAcl(PACL pAcl);
WINADVAPI BOOL WINAPI ADVAPI32$IsValidSid(PSID pSid);

/* KERNEL32 */
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI BOOL  WINAPI KERNEL32$FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI BOOL  WINAPI KERNEL32$FindClose(HANDLE hFindFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);

/* MSVCRT — libc (avoid bare libc; the loader does not resolve it) */
WINBASEAPI void  __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *_Dst, rsize_t _DstSize, const wchar_t *_Src);
WINBASEAPI errno_t __cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
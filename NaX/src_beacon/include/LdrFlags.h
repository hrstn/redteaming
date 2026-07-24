/* beacon/include/LdrFlags.h
 * LDR entry flags for module stomping PEB patching.
 * Shared between Bof/Stomp.c and Commands/BofStomp.c. */

#pragma once

#define LDRP_IMAGE_DLL               0x00000004
#define LDRP_LOAD_NOTIFICATIONS_SENT 0x00000008
#define LDRP_PROCESS_STATIC_IMPORT   0x00000020
#define LDRP_ENTRY_PROCESSED         0x00004000

#ifndef DONT_RESOLVE_DLL_REFERENCES
#define DONT_RESOLVE_DLL_REFERENCES  0x00000001
#endif

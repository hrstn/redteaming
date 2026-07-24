/* beacon/include/WinApis.h
 * Forward declarations for Win32/CRT functions that lack proper prototypes
 * in the MinGW headers included by Instance.h.  Enables D_API() usage
 * for all DLL function pointer struct fields. */

#pragma once

/* msvcrt.dll */
int __cdecl printf( const char*, ... );

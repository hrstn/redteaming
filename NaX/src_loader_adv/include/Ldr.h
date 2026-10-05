#ifndef NAX_ADV_LDR_H
#define NAX_ADV_LDR_H

#include "Defs.h"
#include "Native.h"

FUNC PVOID LdrModulePeb( ULONG Hash );
FUNC PVOID LdrFunction( PVOID Library, ULONG Function );

#endif // NAX_ADV_LDR_H

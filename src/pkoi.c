/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file pkoi.c
 * @author Daax Rynd (daax)
 * @date 1/25/2018 
 */

#include <Windows.h>
#include <ntdef.h>
#include <stdio.h>

#include <ntos.h>
#include <pkortl.h>
#include <pkoi.h>
#include <vm.h>

//! @brief The generic proxy function to replace any IAT entry of the target
unsigned char ProxyFunctionStub[0x1] = {
    0xCC
};

NTSTATUS
WINAPI
PkoiBuildProxyFunction( )
{
    return 0;
}

NTSTATUS
WINAPI
PkoiReplaceIatEntry( )
{
    return 0;
}

NTSTATUS
WINAPI
PkoiInitializeTarget( )
{
    return 0;
}

NTSTATUS
WINAPI
PkoiInitializeTargetApiTable( )
{
    return 0;
}
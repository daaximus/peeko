/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file vm.c
 * @author Daax Rynd (daax)
 * @date 1/28/2018 
 */

#include <minwindef.h>
#include <ntdef.h>
#include <vm.h>

PVOID WINAPI VmSearchTargetForPattern( HANDLE ProcessHandle, PBYTE Pattern, SIZE_T StartAddress, SIZE_T EndAddress )
{
    return NULL;
}

PVOID WINAPI VmCreateCodeCave( PVOID Data, SIZE_T Size )
{
    return NULL;
}

PVOID WINAPI VmGetPebBaseOfTarget( HANDLE ProcessHandle )
{
    return NULL;
}

PVOID WINAPI VmGetTebBaseOfTarget( HANDLE ProcessHandle )
{
    return NULL;
}

NTSTATUS WINAPI VmRemoteCall( PVOID Code, PVOID Arguments, PSIZE_T Result, BOOLEAN Wait )
{
    return 0;
}

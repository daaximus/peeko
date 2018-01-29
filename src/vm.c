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
#include <memoryapi.h>

#include <status.h>
#include <vm.h>
#include <ntos.h>

PVOID
WINAPI
VmSearchTargetForPattern(
    HANDLE ProcessHandle,
    PBYTE Pattern,
    SIZE_T StartAddress,
    SIZE_T EndAddress
)
{
    return NULL;
}

PVOID
WINAPI
VmCreateCodeCave(
    HANDLE ProcessHandle,
    PVOID Data,
    SIZE_T Size
)
{
    NTSTATUS Status;
    SIZE_T BytesWritten;
    PVOID AllocationAddress;

    if (ProcessHandle <= 0)
        return (PVOID)PKO_STATUS_INVALID_HANDLE;

    if (Data == NULL)
        return (PVOID)PKO_STATUS_INVALID_PTR;

    if (Size < PAGE_GRANULARITY)
        Size = PAGE_GRANULARITY;

    AllocationAddress = VirtualAllocEx( ProcessHandle, NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );

    if (AllocationAddress == NULL)
        return (PVOID)PKO_STATUS_BAD_ALLOCATION;

    Status = WriteProcessMemory( ProcessHandle, AllocationAddress, Data, Size, &BytesWritten );

    if(!NT_SUCCESS( Status ))
    {
        VirtualFreeEx( ProcessHandle, AllocationAddress, Size, MEM_RELEASE );
        AllocationAddress = NULL;

        return (PVOID)PKO_STATUS_BAD_WRITE;
    }

    return AllocationAddress;
}

PVOID
WINAPI
VmGetPebBaseOfTarget(
    HANDLE ProcessHandle,
    BOOLEAN isTarget64 )
{
    NTSTATUS Status;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ReturnLength;
    PVOID TargetPebAddress;

    if (isTarget64)
    {
        Status = ZwQueryInformationProcess( ProcessHandle, ProcessBasicInformation, &pbi, sizeof( PROCESS_BASIC_INFORMATION ), &ReturnLength );

        if(!NT_SUCCESS( Status ) || pbi.PebBaseAddress)
            return (PVOID)Status;

        return pbi.PebBaseAddress;
    }
    else
    {
        Status = ZwQueryInformationProcess( ProcessHandle, ProcessWow64Information, &TargetPebAddress, sizeof( SIZE_T ), &ReturnLength );

        if(!NT_SUCCESS( Status ) || !TargetPebAddress)
            return (PVOID)Status;

        return TargetPebAddress;
    }
}

PVOID
WINAPI
VmGetTebBaseOfTarget(
    HANDLE ProcessHandle,
    BOOLEAN isTarget64
)
{
    return NULL;
}

NTSTATUS
WINAPI
VmRemoteCall(
    PVOID Code,
    PVOID Arguments,
    PSIZE_T Result,
    BOOLEAN Wait
)
{
    return 0;
}

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
#include <processthreadsapi.h>
#include <synchapi.h>
#include <rpc.h>

#include <status.h>
#include <vm.h>
#include <ntos.h>

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

NTSTATUS
WINAPI
VmRemoteCall(
    HANDLE ProcessHandle,
    PVOID Code,
    PVOID Arguments,
    PSIZE_T Result,
    BOOLEAN Wait
)
{
    HANDLE ThreadHandle;
    SECURITY_ATTRIBUTES SecurityAttributes;
    ULONG ThreadExitCode;

    if(Code == NULL || ProcessHandle == NULL)
        return PKO_STATUS_INVALID_PARAMETER;

    ThreadHandle = CreateRemoteThread( ProcessHandle, &SecurityAttributes, 0, Code, Arguments, 0, NULL );

    if (ThreadHandle && Wait)
    {
        WaitForSingleObject( ThreadHandle, INFINITE );
        GetExitCodeThread( ThreadHandle, &ThreadExitCode );
    }

    CloseHandle( ThreadHandle );

    return PKO_STATUS_SUCCESS;
}

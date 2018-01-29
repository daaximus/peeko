/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file vm.h
 * @author Daax Rynd (daax)
 * @date 1/28/2018 
 */

#ifndef _VM_H_
#define _VM_H_

/**
 * @name VmSearchTargetForPattern
 * @brief Search the target for specific byte pattern within range [EndAddress - StartAddress]
 * @param ProcessHandle
 * @param Pattern
 * @param StartAddress
 * @param EndAddress
 * @return Address of specified pattern, otherwise NULL for no match
 */
PVOID
WINAPI
VmSearchTargetForPattern(
    HANDLE ProcessHandle,
    PBYTE Pattern,
    SIZE_T StartAddress,
    SIZE_T EndAddress
);

/**
 * @name VmCreateCodeCave
 * @brief Allocate and write code cave into target
 * @param Data
 * @param Size
 * @return Address of code cave allocation
 */
PVOID
WINAPI
VmCreateCodeCave(
    HANDLE ProcessHandle,
    PVOID Data,
    SIZE_T Size
);

/**
 * @name VmRemoteCall
 * @brief Remotely call function using CreateRemoteThread and handling all prerequisite allocations
 * @param Code
 * @param Arguments
 * @return Returns STATUS_SUCCESS when the thread was successfully created and executed
 */
NTSTATUS
WINAPI
VmRemoteCall(
    PVOID Code,
    PVOID Arguments,
    PSIZE_T Result,
    BOOLEAN Wait
);


#endif // _VM_H_

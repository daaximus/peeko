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
 * @param ProcessHandle
 * @param Code
 * @param Arguments
 * @param Result
 * @param Wait
 * @return Returns PKO_STATUS_SUCCESS on successful thread execution, otherwise a PKO status value indicating error
 */
NTSTATUS
WINAPI
VmRemoteCall(
    HANDLE ProcessHandle,
    PVOID Code,
    PVOID Arguments,
    PSIZE_T Result,
    BOOLEAN Wait
);


#endif // _VM_H_

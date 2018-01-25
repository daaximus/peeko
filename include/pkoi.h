/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file pkoi.h
 * @author Daax Rynd (daax)
 * @date 1/25/2018 
 */

#ifndef _PKOI_H_
#define _PKOI_H_

//! @brief The generic proxy function to replace any IAT entry of the target
unsigned char ProxyFunctionStub[0x1] = {
    0xCC
};

/**
 * @name PkoiGetRemoteModuleHandle
 * @brief Acquire the base address of a module in a remote target
 * @param ModuleName
 * @return Target module base address
 */
HMODULE WINAPI PkoiGetRemoteModuleHandle( PCHAR ModuleName );

/**
 * @name PkoiGetModuleHandle
 * @brief Acquire the base address of a module in current process
 * @param ModuleName
 * @return Target module base address
 */
HMODULE WINAPI PkoiGetModuleHandle( PCHAR ModuleName );

/**
 * @name PkoiGetRemoteProcedureAddress
 * @brief Retrieve procedure address in remote module of target
 * @param ModuleBaseAddress
 * @param ProcedureName
 * @return Address of procedure within target module
 */
LPVOID WINAPI PkoiGetRemoteProcedureAddress( HMODULE ModuleBaseAddress, PCHAR ProcedureName );

/**
 * @name PkoiGetProcedureAddress
 * @brief Retrieve procedure address in module of current process
 * @param ModuleBaseAddress
 * @param ProcedureName
 * @return Address of procedure within module of current process
 */
LPVOID WINAPI PkoiGetProcedureAddress( HMODULE ModuleBaseAddress, PCHAR ProcedureName );

/**
 * @name PkoiBuildProxyFunction
 * @brief Fill gaps of ProxyFunctionStub with proper API addresses
 * @return Returns STATUS_SUCCESS if ProxyFunctionStub was filled, otherwise STATUS_FAIL_FAST_EXCEPTION is returned indicating missing information
 */
NTSTATUS WINAPI PkoiBuildProxyFunction( );

/**
 * @name PkoiReplaceIatEntry
 * @brief Replace IAT entry with ProxyFunctionStub in target process
 * @return Returns STATUS_SUCCESS if replacement succeeds, otherwise return value may vary based on error
 */
NTSTATUS WINAPI PkoiReplaceIatEntry( );

/**
 * @name PkoiInitializeTarget
 * @brief Initialize the target process suspended, perform all internal operations, and calls PkoiResumeTarget
 * @return Returns STATUS_SUCCESS once initialization completes
 */
NTSTATUS WINAPI PkoiInitializeTarget( );

/**
 * @name PkoiInitializeTargetApiTable
 * @brief Unimplemented as of yet, will contain operations to fill an API table that will be used to dynamically replace multiple IAT entries
 * @return Undefined
 */
NTSTATUS WINAPI PkoiInitializeTargetApiTable( );

/**
 * @name PkoiResumeTarget
 * @brief  Cleans up extraneous resources and resumes execution of target
 * @return Returns STATUS_SUCCESS if all resources and reinvigoration completes successfully.
 */
NTSTATUS WINAPI PkoiResumeTarget( );

#endif // _PKOI_H_

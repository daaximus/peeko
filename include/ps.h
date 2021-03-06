/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file ps.h
 * @author Daax Rynd (daax)
 * @date 1/29/2018 
 */

#ifndef _PS_H_
#define _PS_H_

//! Process Support specific structures and enumerations

typedef struct _MODULE_INFORMATION
{
    PVOID BaseAddress;
    CHAR ImageName[260];
} MODULE_INFORMATION, *PMODULE_INFORMATION, **PPMODULE_INFORMATION;

typedef enum _FORWARD_INFORMATION
{
    MODULE,
    EXPORT
} FORWARD_INFORMATION;

//! End

/**
 * @name PsGetPebBaseOfTarget
 * @brief --
 * @param ProcessHandle
 * @param isTarget64
 * @return Peb base address of target process
 */
PVOID
WINAPI
PsGetPebBaseOfTarget(
    HANDLE ProcessHandle,
    BOOLEAN isTarget64
);

/**
 * @name PsGetProcessIdByName
 * @brief --
 * @param Name
 * @return Returns the process id of target, otherwise 0 if not found
 */
ULONG
WINAPI
PsGetProcessIdByName(
    PCHAR Name
);

/**
 * @name PsGetRemoteModuleBaseAddress
 * @brief Acquire the base address of a module in a remote target
 * @param ProcessHandle
 * @param isTarget64
 * @param ModuleName
 * @param ModuleSize
 * @return Base address of target module
 */
HMODULE
WINAPI
PsGetRemoteModuleBaseAddress(
    HANDLE ProcessHandle,
    BOOLEAN isTarget64,
    PCHAR ModuleName,
    PSIZE_T ModuleSize
);

/**
 * @name PsGetRemoteProcedureAddress
 * @brief Retrieve procedure address in remote module of target
 * @param ProcessHandle
 * @param isTarget64
 * @param ModuleBaseAddress
 * @param ProcedureName
 * @return Address of procedure in remote process target module
 */
LPVOID
WINAPI
PsGetRemoteProcedureAddress(
    HANDLE ProcessHandle,
    BOOLEAN isTarget64,
    HMODULE ModuleBaseAddress,
    PCHAR ProcedureName
);

/**
 * @name PsGetModuleHandle
 * @brief Acquire the base address of a module in current process
 * @param ModuleName
 * @return Target module base address
 */
HMODULE
WINAPI
PsGetModuleHandle(
    PCHAR ModuleName
);


/**
 * @name PsGetProcedureAddress
 * @brief Retrieve procedure address in module of current process
 * @param ModuleBaseAddress
 * @param ProcedureName
 * @return Address of procedure within module of current process
 */
LPVOID
WINAPI
PsGetProcedureAddress(
    HMODULE ModuleBaseAddress,
    PCHAR ProcedureName
);

/**
 * @name PsGetRemoteModuleInformation
 * @brief Retrieve target module information
 * @param ProcessId
 * @param isTarget64
 * @return Returns a list of of handles for all modules in target
 */
PMODULE_INFORMATION
WINAPI
PsGetRemoteModuleInformation(
    ULONG ProcessId
);


#endif // _PS_H_

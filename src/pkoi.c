/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file pkoi.c
 * @author Daax Rynd (daax)
 * @date 1/25/2018 
 */

#include <Windows.h>

HMODULE WINAPI PkoiGetRemoteModuleHandle( HANDLE ProcessHandle, BOOLEAN isTarget64, PCHAR ModuleName )
{
    return 0;
}

LPVOID WINAPI PkoiGetRemoteProcedureAddress( HANDLE ProcessHandle, BOOLEAN isTarget64, HMODULE ModuleBaseAddress, PCHAR ProcedureName )
{
    return NULL;
}

HMODULE WINAPI PkoiGetModuleHandle( PCHAR ModuleName )
{
    return 0;
}

LPVOID WINAPI PkoiGetProcedureAddress( HMODULE ModuleBaseAddress, PCHAR ProcedureName )
{
    return NULL;
}

NTSTATUS WINAPI PkoiBuildProxyFunction( )
{
    return 0;
}

NTSTATUS WINAPI PkoiReplaceIatEntry( )
{
    return 0;
}

NTSTATUS WINAPI PkoiInitializeTarget( )
{
    return 0;
}

NTSTATUS WINAPI PkoiInitializeTargetApiTable( )
{
    return 0;
}

NTSTATUS WINAPI PkoiResumeTarget( )
{
    return 0;
}
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

#include "../include/ntos.h"
#include "../include/pkortl.h"

HMODULE WINAPI PkoiGetRemoteModuleHandle( HANDLE ProcessHandle, BOOLEAN isTarget64, PCHAR ModuleName )
{
    NTSTATUS Status;
    SIZE_T PebBaseAddress;
    SIZE_T BytesRead;
    ULONG ReturnLength;

    if(isTarget64)
    {
        PROCESS_BASIC_INFORMATION pbi;
        Status = ZwQueryInformationProcess( ProcessHandle, ProcessBasicInformation, &pbi, sizeof( PROCESS_BASIC_INFORMATION ), &ReturnLength );

        PebBaseAddress = (SIZE_T)pbi.PebBaseAddress;

        if(!NT_SUCCESS(Status))
            return (HMODULE)NULL;

        PEB TargetPeb;
        PEB_LDR_DATA TargetLdr;
        if(ReadProcessMemory( ProcessHandle, (LPCVOID)PebBaseAddress, &TargetPeb, sizeof( PEB ), &BytesRead ))
        {
            if( BytesRead && ReadProcessMemory( ProcessHandle, (LPCVOID)TargetPeb.Ldr, &TargetLdr, sizeof( PEB_LDR_DATA ), &BytesRead ))
            {
                SIZE_T LdrHead = (SIZE_T)TargetLdr.InLoadOrderModuleList.Flink;
                SIZE_T LdrNode = (SIZE_T)TargetLdr.InLoadOrderModuleList.Flink;

                LDR_DATA_TABLE_ENTRY TargetLdrDataTableEntry;
                do
                {
                    memset( &TargetLdrDataTableEntry, 0, sizeof( LDR_DATA_TABLE_ENTRY ) );

                    if(!ReadProcessMemory( ProcessHandle, (LPCVOID)LdrNode, &TargetLdrDataTableEntry, sizeof( LDR_DATA_TABLE_ENTRY ), &BytesRead ))
                        return (HMODULE)NULL;

                    LdrNode = (SIZE_T)TargetLdrDataTableEntry.InLoadOrderLinks.Flink;

                    wchar_t TargetModuleName[MAX_PATH];
                    memset( TargetModuleName, 0, MAX_PATH );

                    if(TargetLdrDataTableEntry.BaseDllName.Length)
                        if(!ReadProcessMemory(ProcessHandle, (LPCVOID)TargetLdrDataTableEntry.BaseDllName.Buffer, &TargetModuleName, TargetLdrDataTableEntry.BaseDllName.Length, &BytesRead ))
                            return (HMODULE)NULL;

                    if(TargetLdrDataTableEntry.DllBase)
                        if(!RtlCompareStrings(ModuleName,TargetModuleName))
                            return (HMODULE)TargetLdrDataTableEntry.DllBase;

                } while(LdrHead != LdrNode);
            }
        }
    }
    else
    {
        //
        // 32-bit GMH implementation
        //
    }

    return (HMODULE)NULL;
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
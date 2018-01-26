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
            if(BytesRead && ReadProcessMemory( ProcessHandle, (LPCVOID)TargetPeb.Ldr, &TargetLdr, sizeof( PEB_LDR_DATA ), &BytesRead ))
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

                    if(TargetLdrDataTableEntry.BaseDllName.Length && TargetLdrDataTableEntry.DllBase)
                        if(ReadProcessMemory( ProcessHandle, (LPCVOID)TargetLdrDataTableEntry.BaseDllName.Buffer, &TargetModuleName, TargetLdrDataTableEntry.BaseDllName.Length, &BytesRead ))
                            if(!RtlCompareStrings( ModuleName, TargetModuleName ))
                                return (HMODULE)TargetLdrDataTableEntry.DllBase;

                } while(LdrHead != LdrNode);
            }
        }
    }
    else
    {
        Status = ZwQueryInformationProcess( ProcessHandle, ProcessWow64Information, &PebBaseAddress, sizeof( SIZE_T ), &ReturnLength );

        if(!NT_SUCCESS(Status))
            return (HMODULE)NULL;

        PEB32 TargetPeb;
        PEB_LDR_DATA32 TargetLdr;
        if(ReadProcessMemory( ProcessHandle, (LPCVOID)PebBaseAddress, &TargetPeb, sizeof( PEB32 ), &BytesRead ))
        {
            //
            // Casting to const void* will generate warnings - doesn't matter,
            // it works as needed.
            //
            if(BytesRead && ReadProcessMemory( ProcessHandle, (LPCVOID)TargetPeb.Ldr, &TargetLdr, sizeof( PEB_LDR_DATA32 ), &BytesRead ))
            {
                ULONG LdrHead = (ULONG)TargetLdr.InLoadOrderModuleList.Flink;
                ULONG LdrNode = (ULONG)TargetLdr.InLoadOrderModuleList.Flink;

                LDR_DATA_TABLE_ENTRY32 TargetLdrDataTableEntry;
                do
                {
                    memset( &TargetLdrDataTableEntry, 0, sizeof( LDR_DATA_TABLE_ENTRY32 ) );

                    if(!ReadProcessMemory( ProcessHandle, (LPCVOID)LdrNode, &TargetLdrDataTableEntry, sizeof( LDR_DATA_TABLE_ENTRY ), &BytesRead ))
                        return (HMODULE)NULL;

                    LdrNode = (ULONG)TargetLdrDataTableEntry.InLoadOrderLinks.Flink;

                    wchar_t TargetModuleName[MAX_PATH];
                    memset( TargetModuleName, 0, MAX_PATH );

                    if(TargetLdrDataTableEntry.BaseDllName.Length && TargetLdrDataTableEntry.DllBase)
                        if(ReadProcessMemory( ProcessHandle, (LPCVOID)TargetLdrDataTableEntry.BaseDllName.Buffer, &TargetModuleName, TargetLdrDataTableEntry.BaseDllName.Length, &BytesRead ))
                            if(!RtlCompareStrings( ModuleName, TargetModuleName ))
                                return (HMODULE)TargetLdrDataTableEntry.DllBase;


                } while(LdrHead != LdrNode);
            }
        }
    }

    return (HMODULE)NULL;
}

LPVOID WINAPI PkoiGetRemoteProcedureAddress( HANDLE ProcessHandle, BOOLEAN isTarget64, HMODULE ModuleBaseAddress, PCHAR ProcedureName )
{
    return NULL;
}

HMODULE WINAPI PkoiGetModuleHandle( PCHAR ModuleName )
{
    SIZE_T PresentPebLdrList = __readgsqword( 0x60 );
    PresentPebLdrList = *(SIZE_T *)(PresentPebLdrList + 0x18);

    PLDR_DATA_TABLE_ENTRY InLoadOrderModules = *(PLDR_DATA_TABLE_ENTRY *)(PresentPebLdrList + 0x10);
    for(; InLoadOrderModules->DllBase; InLoadOrderModules = (PLDR_DATA_TABLE_ENTRY)InLoadOrderModules->InLoadOrderLinks.Flink)
    {
        if(!RtlCompareStrings( ModuleName, InLoadOrderModules->BaseDllName.Buffer ))
            return (HMODULE)InLoadOrderModules->DllBase;
    }

    return (HMODULE)NULL;
}

LPVOID WINAPI PkoiGetProcedureAddress( HMODULE ModuleBaseAddress, PCHAR ProcedureName )
{
    SIZE_T ProcedureAddress = 0;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBaseAddress;

    if(DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)((LPBYTE)ModuleBaseAddress + DosHeader->e_lfanew);

    if(NtHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)ModuleBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    ULONG ExportDirectorySize = (ULONG)((LPBYTE)ModuleBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

    for(UINT iter = 0; iter < ExportDirectory->NumberOfNames; iter++)
    {
        ULONG *ExportNameTable = (ULONG *)((LPBYTE)ModuleBaseAddress + ExportDirectory->AddressOfNames);
        PCHAR ExportName = (PCHAR)((SIZE_T)ModuleBaseAddress + (ULONG)ExportNameTable[iter]);

        if(!strcmp( ProcedureName, ExportName ))
        {
            ULONG *ExportOridinalTable = (ULONG *)((LPBYTE)ModuleBaseAddress + ExportDirectory->AddressOfNameOrdinals);
            WORD NameOrdinal = (WORD)((SIZE_T)ModuleBaseAddress + (USHORT)ExportOridinalTable[iter]);

            SIZE_T *ExportAddressTable = (SIZE_T *)((LPBYTE)ModuleBaseAddress + ExportDirectory->AddressOfFunctions);
            ProcedureAddress = ((SIZE_T)ModuleBaseAddress + ExportAddressTable[NameOrdinal]);

            return (LPVOID)ProcedureAddress;
        }
    }

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
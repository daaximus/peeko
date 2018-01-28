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

#include <ntos.h>
#include <pkortl.h>
#include <pkoi.h>

//! @brief The generic proxy function to replace any IAT entry of the target
unsigned char ProxyFunctionStub[0x1] = {
    0xCC
};

HMODULE
WINAPI
PkoiGetRemoteModuleHandle(
    HANDLE ProcessHandle,
    BOOLEAN isTarget64,
    PCHAR ModuleName
)
{
    NTSTATUS Status;
    SIZE_T PebBaseAddress;
    SIZE_T BytesRead;
    ULONG ReturnLength;

    if (isTarget64)
    {
        PROCESS_BASIC_INFORMATION pbi;
        Status = ZwQueryInformationProcess( ProcessHandle, ProcessBasicInformation, &pbi, sizeof( PROCESS_BASIC_INFORMATION ), &ReturnLength );

        PebBaseAddress = (SIZE_T)pbi.PebBaseAddress;

        if (!NT_SUCCESS(Status))
            return (HMODULE)NULL;

        PEB TargetPeb;
        PEB_LDR_DATA TargetLdr;
        if (ReadProcessMemory( ProcessHandle, (LPCVOID)PebBaseAddress, &TargetPeb, sizeof( PEB ), &BytesRead ))
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

        if (!NT_SUCCESS(Status))
            return (HMODULE)NULL;

        PEB32 TargetPeb;
        PEB_LDR_DATA32 TargetLdr;
        if (ReadProcessMemory( ProcessHandle, (LPCVOID)PebBaseAddress, &TargetPeb, sizeof( PEB32 ), &BytesRead ))
        {
            //
            // Casting to const void* will generate warnings - doesn't matter,
            // it works as needed.
            //
            if (BytesRead && ReadProcessMemory( ProcessHandle, (LPCVOID)TargetPeb.Ldr, &TargetLdr, sizeof( PEB_LDR_DATA32 ), &BytesRead ))
            {
                ULONG LdrHead = (ULONG)TargetLdr.InLoadOrderModuleList.Flink;
                ULONG LdrNode = (ULONG)TargetLdr.InLoadOrderModuleList.Flink;

                LDR_DATA_TABLE_ENTRY32 TargetLdrDataTableEntry;
                do
                {
                    memset( &TargetLdrDataTableEntry, 0, sizeof( LDR_DATA_TABLE_ENTRY32 ) );

                    if (!ReadProcessMemory( ProcessHandle, (LPCVOID)LdrNode, &TargetLdrDataTableEntry, sizeof( LDR_DATA_TABLE_ENTRY ), &BytesRead ))
                        return (HMODULE)NULL;

                    LdrNode = (ULONG)TargetLdrDataTableEntry.InLoadOrderLinks.Flink;

                    wchar_t TargetModuleName[MAX_PATH];
                    memset( TargetModuleName, 0, MAX_PATH );

                    if (TargetLdrDataTableEntry.BaseDllName.Length && TargetLdrDataTableEntry.DllBase)
                        if (ReadProcessMemory( ProcessHandle, (LPCVOID)TargetLdrDataTableEntry.BaseDllName.Buffer, &TargetModuleName, TargetLdrDataTableEntry.BaseDllName.Length, &BytesRead ))
                            if (!RtlCompareStrings( ModuleName, TargetModuleName ))
                                return (HMODULE)TargetLdrDataTableEntry.DllBase;


                } while (LdrHead != LdrNode);
            }
        }
    }

    return (HMODULE)NULL;
}

LPVOID
WINAPI
PkoiGetRemoteProcedureAddress(
    HANDLE ProcessHandle,
    BOOLEAN isTarget64,
    HMODULE ModuleBaseAddress,
    PCHAR ProcedureName
)
{
    //
    // Target neutral structures and types
    //
    BYTE ModuleBuffer[PAGE_GRANULARITY];
    SIZE_T BytesRead;
    PIMAGE_DOS_HEADER DosHeader;
    ULONG ExportDirectorySize;
    USHORT ExportOrdinal;
    CHAR Name[MAX_PATH];
    CHAR ForwardedExport[MAX_PATH];
    PCHAR *ForwardInformation;
    HMODULE ForwardModuleBase;

    //
    // 64-bit target structures and types
    //
    PIMAGE_NT_HEADERS64 NtHeader;
    IMAGE_EXPORT_DIRECTORY ExportDirectory;
    SIZE_T ExportDirectoryAddress;
    SIZE_T ExportNamePointerTable64;
    SIZE_T ExportName64;
    PVOID ExportAddress64;

    //
    // 32-bit target structures and types
    //
    PIMAGE_NT_HEADERS32 NtHeader32;
    ULONG ExportDirectoryAddress32;
    ULONG ExportNamePointerTable32;
    ULONG ExportName32;
    ULONG ExportAddress32;

    //
    // The first page of the module will be the same amount of
    // information across architectures
    //
    if (!ReadProcessMemory( ProcessHandle, ModuleBaseAddress, &ModuleBuffer, PAGE_GRANULARITY, &BytesRead ))
        return NULL;

    DosHeader = (PIMAGE_DOS_HEADER)ModuleBuffer;

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    if (isTarget64)
    {
        NtHeader = (PIMAGE_NT_HEADERS64)(ModuleBuffer + DosHeader->e_lfanew);

        if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        ExportDirectoryAddress = (SIZE_T)ModuleBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportDirectorySize = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (!ReadProcessMemory( ProcessHandle, (LPCVOID)ExportDirectoryAddress, &ExportDirectory, sizeof( IMAGE_EXPORT_DIRECTORY ), &BytesRead ))
            return NULL;

        for (unsigned int iter = 0; iter < ExportDirectory.NumberOfNames; iter++)
        {
            if (!ReadProcessMemory( ProcessHandle, (LPCVOID)((SIZE_T)ModuleBaseAddress + ExportDirectory.AddressOfNames + (ULONG)(iter * sizeof( ULONG ))), &ExportNamePointerTable64, sizeof( ULONG ), &BytesRead ))
                return NULL;

            memset( Name, 0, MAX_PATH );
            ExportName64 = (SIZE_T)ModuleBaseAddress + ExportNamePointerTable64;
            if (!ReadProcessMemory( ProcessHandle, (LPCVOID)ExportName64, &Name, MAX_PATH, &BytesRead ))
                return NULL;

            if (!ReadProcessMemory( ProcessHandle, (LPCVOID)((SIZE_T)ModuleBaseAddress + ExportDirectory.AddressOfNameOrdinals + (ULONG)(iter * sizeof( USHORT ))), &ExportOrdinal, sizeof( ULONG ), &BytesRead ))
                return NULL;

            if (!strcmp( ProcedureName, Name ))
            {
                if (!ReadProcessMemory( ProcessHandle, (LPCVOID)((SIZE_T)ModuleBaseAddress + ExportDirectory.AddressOfFunctions + (ExportOrdinal * sizeof( ULONG ))), &ExportAddress64, sizeof( ULONG ), &BytesRead ))
                    return NULL;

                ExportAddress64 = (PVOID)((SIZE_T)ModuleBaseAddress + ExportAddress64);

                if (ExportAddress64 >= (PVOID)ExportDirectoryAddress &&
                    ExportAddress64 <= (PVOID)(ExportDirectoryAddress + ExportDirectorySize))
                {
                    if (!ReadProcessMemory( ProcessHandle, (LPCVOID)ExportAddress64, &ForwardedExport, sizeof( ForwardedExport ), &BytesRead ))
                        return NULL;

                    ForwardInformation = RtlProcessForwardedExport( ForwardedExport );
                    ForwardModuleBase = PkoiGetRemoteModuleHandle( ProcessHandle, TRUE, ForwardInformation[MODULE] );

                    ExportAddress64 = PkoiGetRemoteProcedureAddress( ProcessHandle, TRUE, ForwardModuleBase, ForwardInformation[EXPORT] );
                }
                return (LPVOID)ExportAddress64;
            }
        }
    }
    else
    {
        NtHeader32 = (PIMAGE_NT_HEADERS32)(ModuleBuffer + DosHeader->e_lfanew);

        if (NtHeader32->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        ExportDirectoryAddress32 = (ULONG)ModuleBaseAddress + NtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportDirectorySize = NtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (!ReadProcessMemory( ProcessHandle, (LPCVOID)ExportDirectoryAddress32, &ExportDirectory, sizeof( IMAGE_EXPORT_DIRECTORY ), &BytesRead ))
            return NULL;

        for (unsigned int iter = 0; iter < ExportDirectory.NumberOfNames; iter++)
        {
            if (!ReadProcessMemory( ProcessHandle, (LPCVOID)((ULONG)ModuleBaseAddress + ExportDirectory.AddressOfNames + (ULONG)(iter * sizeof( ULONG ))), &ExportNamePointerTable32, sizeof( ULONG ), &BytesRead ))
                return NULL;

            memset( Name, 0, MAX_PATH );
            ExportName32 = (ULONG)ModuleBaseAddress + ExportNamePointerTable32;
            if (!ReadProcessMemory( ProcessHandle, (LPCVOID)ExportName32, &Name, MAX_PATH, &BytesRead ))
                return NULL;

            if (!ReadProcessMemory( ProcessHandle, (LPCVOID)((ULONG)ModuleBaseAddress + ExportDirectory.AddressOfNameOrdinals + (ULONG)(iter * sizeof( USHORT ))), &ExportOrdinal, sizeof( USHORT ), &BytesRead ))
                return NULL;

            if (!strcmp( ProcedureName, Name ))
            {
                if (!ReadProcessMemory( ProcessHandle, (LPCVOID)((ULONG)ModuleBaseAddress + ExportDirectory.AddressOfFunctions + (ExportOrdinal * sizeof( ULONG ))), &ExportAddress32, sizeof( ULONG ), &BytesRead ))
                    return NULL;

                ExportAddress32 = (ULONG)ModuleBaseAddress + ExportAddress32;

                if (ExportAddress32 >= ExportDirectoryAddress32 &&
                    ExportAddress32 <= ExportDirectoryAddress32 + ExportDirectorySize)
                {
                    if (!ReadProcessMemory( ProcessHandle, (LPCVOID)ExportAddress32, &ForwardedExport, sizeof( ForwardedExport ), &BytesRead ))
                        return NULL;

                    ForwardInformation = RtlProcessForwardedExport( ForwardedExport );
                    ForwardModuleBase = PkoiGetRemoteModuleHandle( ProcessHandle, FALSE, ForwardInformation[MODULE] );

                    ExportAddress32 = (ULONG)PkoiGetRemoteProcedureAddress( ProcessHandle, FALSE, ForwardModuleBase, ForwardInformation[EXPORT] );
                }
                return (LPVOID)ExportAddress32;
            }
        }
    }

    return NULL;
}

HMODULE
WINAPI
PkoiGetModuleHandle(
    PCHAR ModuleName
)
{
    SIZE_T PresentPebLdrList = __readgsqword( 0x60 );
    PresentPebLdrList = *(SIZE_T *)(PresentPebLdrList + 0x18);

    PLDR_DATA_TABLE_ENTRY InLoadOrderModules = *(PLDR_DATA_TABLE_ENTRY *)(PresentPebLdrList + 0x10);
    for (; InLoadOrderModules->DllBase; InLoadOrderModules = (PLDR_DATA_TABLE_ENTRY)InLoadOrderModules->InLoadOrderLinks.Flink)
    {
        if (!RtlCompareStrings( ModuleName, InLoadOrderModules->BaseDllName.Buffer ))
            return (HMODULE)InLoadOrderModules->DllBase;
    }

    return (HMODULE)NULL;
}

LPVOID
WINAPI
PkoiGetProcedureAddress(
    HMODULE ModuleBaseAddress,
    PCHAR ProcedureName
)
{
    SIZE_T ProcedureAddress = 0;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBaseAddress;

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)((LPBYTE)ModuleBaseAddress + DosHeader->e_lfanew);

    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)ModuleBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    ULONG ExportDirectorySize = (ULONG)((LPBYTE)ModuleBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

    for (UINT iter = 0; iter < ExportDirectory->NumberOfNames; iter++)
    {
        ULONG *ExportNameTable = (ULONG *)((LPBYTE)ModuleBaseAddress + ExportDirectory->AddressOfNames);
        PCHAR ExportName = (PCHAR)((SIZE_T)ModuleBaseAddress + (ULONG)ExportNameTable[iter]);

        if (!strcmp( ProcedureName, ExportName ))
        {
            ULONG* ExportOridinalTable = (ULONG*)((LPBYTE)ModuleBaseAddress + ExportDirectory->AddressOfNameOrdinals);
            WORD NameOrdinal = (WORD)((SIZE_T)ModuleBaseAddress + (USHORT)ExportOridinalTable[iter]);

            SIZE_T* ExportAddressTable = (SIZE_T*)((LPBYTE)ModuleBaseAddress + ExportDirectory->AddressOfFunctions);
            ProcedureAddress = ((SIZE_T)ModuleBaseAddress + ExportAddressTable[NameOrdinal]);

            if (ProcedureAddress >= (SIZE_T)ExportDirectory &&
                ProcedureAddress <= (SIZE_T)ExportDirectory + ExportDirectorySize)
            {
                PCHAR ForwardModule = (PCHAR)ProcedureAddress;

                PCHAR *ForwardInformation = RtlProcessForwardedExport( ForwardModule );
                HMODULE ForwardModuleBase;

                //
                // If the module is not already present, load it
                //
                if (!PkoiGetModuleHandle( ForwardInformation[0] ))
                {
                    ForwardModuleBase = LoadLibrary( ForwardInformation[0] );
                }
                else
                {
                    //
                    // If it's already present, grab the base of the module
                    //
                    ForwardModuleBase = PkoiGetModuleHandle( ForwardInformation[0] );
                }

                ProcedureAddress = (SIZE_T)PkoiGetProcedureAddress( ForwardModuleBase, ForwardInformation[1] );
            }

            return (LPVOID)ProcedureAddress;
        }
    }

    return NULL;
}

NTSTATUS
WINAPI
PkoiBuildProxyFunction( )
{
    return 0;
}

NTSTATUS
WINAPI
PkoiReplaceIatEntry( )
{

    return 0;
}

NTSTATUS
WINAPI
PkoiInitializeTarget( )
{
    return 0;
}

NTSTATUS
WINAPI
PkoiInitializeTargetApiTable( )
{
    return 0;
}

NTSTATUS
WINAPI
PkoiResumeTarget( )
{
    return 0;
}
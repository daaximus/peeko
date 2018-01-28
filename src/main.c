#include <windows.h>
#include <stdio.h>

#include "../include/pkoi.h"

VOID
WINAPI
PkoUsage( );

NTSTATUS
WINAPI
PkoValidateArguments( );

NTSTATUS
WINAPI
PkoSetTaskFlags( );

int
main(
    int argc,
    char** argv,
    char** envp
)
{
    printf( "[*] Please ensure this tool is running with administrative privileges!\n" );

    //
    // test code, doesn't matter what's here
    //
    HANDLE p = OpenProcess( PROCESS_ALL_ACCESS, 0, 352 );

    HMODULE mod = PkoiGetRemoteModuleHandle( p, TRUE, "kernel32.dll" );
    PVOID final = PkoiGetRemoteProcedureAddress( p, TRUE, mod, "HeapAlloc" );

    return 0;
}
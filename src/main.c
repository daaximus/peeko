#include <windows.h>
#include <stdio.h>

#include "../include/pkoi.h"

VOID WINAPI PkoUsage( );
NTSTATUS WINAPI PkoValidateArguments( );
NTSTATUS WINAPI PkoSetTaskFlags( );

int main( int argc, char** argv, char** envp )
{
    printf( "[*] Please ensure this tool is running with administrative privileges!\n" );

    HANDLE p = OpenProcess( PROCESS_ALL_ACCESS, 0, 12396 );
    printf( "%llx\n", (ULONGLONG)PkoiGetRemoteModuleHandle( p, FALSE, "kernel32.dll" ) );

    return 0;
}
#include <windows.h>
#include <stdio.h>

#include <ps.h>
#include <vm.h>

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

    return 0;
}
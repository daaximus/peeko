/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file pkortl.c
 * @author Daax Rynd (daax)
 * @date 1/25/2018 
 */

#include <minwindef.h>

DWORD
WINAPI
RtlCompareStrings(
    PCHAR StringA,
    PWCHAR StringB
)
{
	const char *szIterA = StringA; const wchar_t *szIterB = StringB;

	while( *szIterA ) {
		if( (*szIterA++ | 0x60) != (*szIterB++ | 0x60) )
			return 1;
	}

	return *szIterB;
}

DWORD
WINAPI
RtlGetStringLength(
    PCHAR String
)
{
    DWORD Iter = 0;
    while( String[ Iter++ ] );
    return Iter;
}

PCHAR *
WINAPI
RtlProcessForwardedExport(
    PCHAR ForwardedExport
)
{
    //
    // Allocate memory for a two element array of pointers to c-strings
    //
    PCHAR *ForwardInformation = (PCHAR *)malloc( sizeof( PCHAR ) * 2 );

    //
    // Get entire forwarded export name
    // e.g. NTDLL.HeapAlloc
    //
    unsigned int ForwardModuleLength = RtlGetStringLength( ForwardedExport ) - 1;
    unsigned int ModuleLength = 0, ProcedureLength = 0;

    //
    // Determine length of module name appended to front
    // of export name
    //
    for(; ForwardedExport[++ModuleLength] != '.';);

    //
    // Calculate procedure name length for allocations
    //
    ProcedureLength = ForwardModuleLength - ModuleLength;

    ForwardInformation[0] = (PCHAR)malloc( sizeof( PCHAR ) * ModuleLength + 5 );
    ForwardInformation[1] = (PCHAR)malloc( sizeof( PCHAR ) * ProcedureLength + 1 );


    for(unsigned int iter = 0; iter < ForwardModuleLength; iter++)
    {
        if(iter < ModuleLength)
            ForwardInformation[0][iter] = (char)(ForwardedExport[iter] | 0x60);

        if(iter > ModuleLength)
            ForwardInformation[1][iter - ModuleLength - 1] = (char)(ForwardedExport[iter]);
    }

    //
    // Append extension to forwarded module name
    //
    CHAR Extension[0x5] = ".dll";
    for(unsigned int iter = 0; iter < 5; iter++)
            ForwardInformation[0][ModuleLength + iter] = Extension[iter];

    ForwardInformation[1][ProcedureLength-1] = '\0';

    return ForwardInformation;
}
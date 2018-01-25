/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file pkortl.c
 * @author Daax Rynd (daax)
 * @date 1/25/2018 
 */

#include <minwindef.h>

DWORD WINAPI RtlCompareStrings( PCHAR StringA, PWCHAR StringB )
{
	const char *szIterA = StringA; const wchar_t *szIterB = StringB;

	while( *szIterA ) {
		if( (*szIterA++ | 0x60) != (*szIterB++ | 0x60) )
			return 1;
	}

	return *szIterB;
}
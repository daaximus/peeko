/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file pkortl.h
 * @author Daax Rynd (daax)
 * @date 1/25/2018 
 */

#ifndef _PKORTL_H_
#define _PKORTL_H_

/**
 * @name RtlCompareStrings
 * @brief Compares string with unicode counterpart
 * @param StringA
 * @param StringB
 * @return Returns > 0 if strings match, otherwise 0
 */
DWORD
WINAPI
RtlCompareStrings(
    PCHAR StringA,
    PWCHAR StringB
);

/**
 * @name RtlGetStringLength
 * @brief Quickly determines string length of an ANSI string
 * @param String
 * @return Returns string length
 */
DWORD
WINAPI
RtlGetStringLength(
    PCHAR String
);

/**
 * @name RtlProcessForwardedExport
 * @brief Pulls apart the two components of a forwarded export for use in subsequent function calls
 * @param ForwardedExport
 * @return Returns an array of c-strings containing the forwarded export module ([0]) and name ([1])
 */
PCHAR *
WINAPI
RtlProcessForwardedExport(
    PCHAR ForwardedExport
);

/**
 * @name RtlGetNtHeaderNeutral
 * @brief --
 * @param BaseAddress
 * @return Returns pointer to PE header for target, architecture neutral
 */
PVOID
WINAPI
RtlGetNtHeaderNeutral(
    PVOID BaseAddress
);


#endif // _PKORTL_H_

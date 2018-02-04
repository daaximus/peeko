/**
 * peeko
 * Copyright (c) 2018 Daax Rynd. All rights reserved.
 *
 * @file proxy.h
 * @author Daax Rynd (daax)
 * @date 1/30/2018 
 */

#ifndef _PROXY_H_
#define _PROXY_H_

typedef struct _PKO_API_ENTRY
{
    void *ApiAddress;
    void *ModAddress;
    char ModuleName[255];
} PKO_API_ENTRY, *PPKO_API_ENTRY;

extern unsigned long  gApiTableEntries;
extern PPKO_API_ENTRY gApiTable;

void *ProxyEntry( void );

#endif // _PROXY_H_

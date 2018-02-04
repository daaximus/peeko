;++
; peeko
; Copyright (c) 2018 Daax Rynd. All rights reserved.
;
; @file proxy.asm.asm
; @author Daax Rynd (daax)
; @date 1/30/2018 
;--

extern CreateFile
extern WriteFile
extern CloseHandle

extern gApiTable
extern gApiTableEntries

SECTION .data
[BITS 64]

SECTION .text
[BITS 64]

struc PKO_API_ENTRY
    .ApiAddress             resq    1
    .ModAddress             resq    1
    .ModuleName             resb    255
    .Size:
endstruc

global ProxyEntry
ProxyEntry:
    push rbp
    sub rsp, 0x80
    ;
    ; mov r11, [gApiTable]
    ; mov rax, [r11+PKO_API_ENTRY.ApiAddress]
    ;
    ; to be implemented
    ;
    add rsp, 0x80
    pop rbp
    ret
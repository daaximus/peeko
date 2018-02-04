;++
; peeko
; Copyright (c) 2018 Daax Rynd. All rights reserved.
;
; @file ntos.asm.asm
; @author Daax Rynd (daax)
; @date 1/25/2018 
;--

section .text
[BITS 64]

;
; all syscall indexes used are correct for 1703 and 1709
;

global ZwQuerySystemInformation
ZwQuerySystemInformation:
	mov r10, rcx
	mov eax, 36h
	syscall
	ret

global ZwQueryInformationProcess
ZwQueryInformationProcess:
	mov r10, rcx
	mov eax, 19h
	syscall
	ret

global ZwQueryInformationThread
ZwQueryInformationThread:
	mov r10, rcx
	mov eax, 25h
	syscall
	ret

global ZwQueryVirtualMemory
ZwQueryVirtualMemory:
	mov r10, rcx
	mov eax, 23h
	syscall
	ret

global ZwQueryObject
ZwQueryObject:
	mov r10, rcx
	mov eax, 10h
	syscall
	ret

global ZwProtectVirtualMemory
ZwProtectVirtualMemory:
	mov r10, rcx
	mov eax, 50h
	syscall
	ret

global ZwAllocateVirtualMemory
ZwAllocateVirtualMemory:
	mov r10, rcx
	mov eax, 18h
	syscall
	ret

global ZwFreeVirtualMemory
ZwFreeVirtualMemory:
	mov r10, rcx
	mov eax, 1Eh
	syscall
	ret

global ZwMapViewOfSection
ZwMapViewOfSection:
	mov r10, rcx
	mov eax, 28h
	syscall
	ret

global ZwUnmapViewOfSection
ZwUnmapViewOfSection:
	mov r10, rcx
	mov eax, 2Ah
	syscall
	ret

global ZwCreateThread
ZwCreateThread:
	mov r10, rcx
	mov eax, 4Eh
	syscall
	ret

global ZwOpenSection
ZwOpenSection:
	mov r10, rcx
	mov eax, 37h
	syscall
	ret

global ZwOpenProcess
ZwOpenProcess:
	mov r10, rcx
	mov eax, 26h
	syscall
	ret

global ZwSetSystemInformation
ZwSetSystemInformation:
	mov r10, rcx
	mov eax, 19Dh
	syscall
	ret

global ZwSetInformationProcess
ZwSetInformationProcess:
	mov r10, rcx
	mov eax, 1Ch
	syscall
	ret

global ZwSetInformationObject
ZwSetInformationObject:
	mov r10, rcx
	mov eax, 5Ch
	syscall
	ret

global ZwSetInformationThread
ZwSetInformationThread:
	mov r10, rcx
	mov eax, 0Dh
	syscall
	ret

global ZwSetInformationVirtualMemory
ZwSetInformationVirtualMemory:
	mov r10, rcx
	mov eax, 191h
	syscall
	ret

global ZwDuplicateObject
ZwDuplicateObject:
	mov r10, rcx
	mov eax, 3Ch
	syscall
	ret

global ZwTerminateProcess
ZwTerminateProcess:
	mov r10, rcx
	mov eax, 7002Ch
	syscall
	ret

global ZwTerminateThread
ZwTerminateThread:
	mov r10, rcx
	mov eax, 70053h
	syscall
	ret

global ZwClose
ZwClose:
	mov r10, rcx
	mov eax, 3000Fh
	syscall
	ret

global ZwDelayExecution
ZwDelayExecution:
	mov r10, rcx
	mov eax, 34h
	syscall
	ret
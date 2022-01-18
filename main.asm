;==================
;  ASM Functions 
;==================

include header.inc


.code 

;; Getting DebuggerFlag from PEB

IsDbgPresent PROC
	xor rax, rax
	mov rax, gs:[OFFSET_PEB]	  ; RAX = Offset of PEB
    movzx rax, BYTE PTR [rax+DBG_Flag]  ; RAX = PEB + 0x02 = DebuggerFlag
	ret
IsDbgPresent ENDP



 ;=========================================================
 ; Get NTDLL Base Via PEB->LDR->InmemoryModuleList Parsing
 ;=========================================================

GetNTDLLBase PROC
  xor rdi, rdi                  ; RDI = 0x0
  mul rdi                       ; RAX&RDX =0x0
  mov rbx, gs:[rax+OFFSET_PEB]  ; RBX = Address_of_PEB
  mov rbx, [rbx+OFFSET_LDR_DATA]; RBX = Address_of_LDR
  mov rbx, [rbx+20h]            ; 
  mov rbx, [rbx]                ; RBX = 1st entry in InitOrderModuleList / ntdll.dll
  mov rbx, [rbx+20h]            ; RBX = &ntdll.dll ( Base Address of ntdll.dll)
  mov rax, rbx                  ; RBX & RAX = &ntdll.dll
  ret                           ; return to caller
GetNTDLLBase ENDP


 ;==================
 ; Get Process Heap
 ;==================

x64_get_process_heap PROC
push rbp
mov rbp, rsp
sub rsp, 8 * 2
mov rax, gs:[60h]
mov rax, [rax + 30h]
mov rsp, rbp
pop rbp
ret
x64_get_process_heap ENDP

 ;============================================================
 ; Get Kernel32 Base Via PEB->LDR->InmemoryModuleList Parsing
 ;============================================================

GetK32ModuleHandle PROC
	mov		rax, gs:[60h]       ; PEB
	mov		rax, [rax + 18h]    ; Ldr
	mov		rax, [rax + 20h]    ; InMemoryOrderModuleList
	mov		rax, [rax]          ; Skip 'this' module and get to ntdll
	mov		rax, [rax]          ; Skip ntdll module and get to kernel32
	mov		rax, [rax + 20h]    ; DllBase for kernel32 --- size_t offset = offsetof(LDR_DATA_TABLE_ENTRY, DllBase) - sizeof(LIST_ENTRY);
	ret
GetK32ModuleHandle ENDP



 ;=============================================================================================
 ; GetProcAddress - https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/
 ;=============================================================================================


GetAddressOf_GetProcAddress PROC

xor r8,  r8                 ; Clear r8
xor rbx, rbx
mov rbx, rcx
mov r8d, [rbx + 3h]        ; R8D = DOS->e_lfanew offset
mov rdx, r8                ; RDX = DOS->e_lfanew
add rdx, rbx               ; RDX = PE Header
mov r8d, [rdx + 88h]       ; R8D = Offset export table
add r8, rbx                ; R8 = Export table
xor rsi, rsi               ; Clear RSI
mov esi, [r8 + 20h]        ; RSI = Offset namestable
add rsi, rbx               ; RSI = Names table
xor rcx, rcx               ; RCX = 0
mov r9, 41636f7250746547h  ; GetProcA

; Loop through exported functions and find GetProcAddress

Get_Function:

inc rcx                    ; Increment the ordinal
xor rax, rax               ; RAX = 0
mov eax, [rsi + rcx * 4]   ; Get name offset
add rax, rbx               ; Get function name
cmp [rax], r9              ; GetProcA ?
jnz Get_Function
xor rsi, rsi               ; RSI = 0
mov esi, [r8 + 24h]        ; ESI = Offset ordinals
add rsi, rbx               ; RSI = Ordinals table
mov cx, [rsi + rcx * 2]    ; Number of function
xor rsi, rsi               ; RSI = 0
mov esi, [r8 + 1ch]        ; Offset address table
add rsi, rbx               ; ESI = Address table
xor rdx, rdx               ; RDX = 0
mov edx, [rsi + rcx * 4]   ; EDX = Pointer(offset)
add rdx, rbx               ; RDX = GetProcAddress
mov rdi, rdx               ; Save GetProcAddress in RDI
mov rax, rdi
ret

GetAddressOf_GetProcAddress ENDP


GetENVAddr PROC
xor rdi, rdi                    ; RDI = 0x0
  mul rdi                       ; RAX&RDX =0x0
  mov rbx, gs:[rax+60h]         ; RBX = Address_of_PEB
  mov rax, [rbx+20h]
  ret
GetENVAddr ENDP

end

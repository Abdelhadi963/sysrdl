; assembly/RDLStub.asm

PUBLIC GetImageBaseAsm

.DATA

.CODE

; GetImageBaseAsm: returns the current process image base in RAX
GetImageBaseAsm PROC
    mov rax, gs:[30h]       ; TEB base
    mov rax, [rax + 60h]    ; PEB pointer
    mov rax, [rax + 10h]    ; PEB->ImageBaseAddress
    ret
GetImageBaseAsm ENDP

END

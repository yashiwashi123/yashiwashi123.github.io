section .text
global _start

_start:
    ; Place your shellcode here
    ; Replace shellcode with your binary shellcode
    shellcode:
        db 0x48, 0xc0, 0x31, 0x48, 0x31, 0x48, 0xda, 0x31, 0x3e, 0x8b, 0x9c, 0x91, 0xba, 0x00, 0x00, 0x00
        db 0x48, 0x00, 0x00, 0x00, 0xb8, 0xeb, 0xd0, 0xff, 0x11, 0xdf

    ; Call the shellcode
    call shellcode

    ; Exit the program
    mov eax, 60
    xor edi, edi
    syscall
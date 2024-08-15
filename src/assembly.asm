BITS 64

SECTION .data
    msg db 'Je suis trop un hacker', 0
SECTION .text
global main

main:
    ;save context
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11 

    ;write syscall
    mov rax, 1 
    mov rdi, 1 
    lea rsi, [rel msg] 
    mov rdx, 22 
    syscall

    ;load context
    pop r11
    pop rdi 
    pop rsi
    pop rdx
    pop rcx
    pop rax

    ;mov rax, 0x4022e0
    ;jump 
    ;jmp rax

    ret
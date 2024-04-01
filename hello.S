bits 64
_start:
	mov rax, -1
	syscall
	mov rax, 0x3c
	xor rdi, rdi
	syscall

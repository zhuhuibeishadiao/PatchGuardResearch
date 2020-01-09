.CODE

__ror64 PROC
	push rcx
	xor rax,rax
	mov rax,rcx
	xor rcx,rcx
	mov rcx,rdx
	ror rax,cl
	pop rcx
	ret
__ror64 ENDP

__btc64 PROC
	xor rax,rax
	mov rax,rcx
	btc rax,rax
	ret
__btc64 ENDP

__btr64 PROC
	xor rax,rax
	mov rax,rcx
	btr rax,rax
	ret
__btr64 ENDP

END
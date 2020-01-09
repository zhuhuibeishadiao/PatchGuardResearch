.CODE

__ror64 PROC
	mov rax,rcx
	mov rcx,rdx
	ror rax,cl
	ret
__ror64 ENDP

__btc64 PROC
	btc rcx,rdx
	mov rax,rcx
	ret
__btc64 ENDP

END
bits 32
org 0
%include "constants.inc"

%define IAT_CREATE  (0x1000 + 0*4)
%define IAT_READ    (0x1000 + 1*4)
%define IAT_CLOSE   (0x1000 + 2*4)
%define IAT_MSG     (0x1000 + 3*4)
%define IAT_EXIT    (0x1000 + 4*4)
%define IAT_VEH     (0x1000 + 5*4)
%define XTEA_TRANSFER_MASK 0x6B8F20D5

; Preserve the tested TLS layout, including all junk blocks and offsets.
callback:
    push ebp
    mov ebp, esp
    cmp dword [ebp+12], 1
    jne short callback_return
    call callback_anchor
callback_anchor:
    pop esi
    lea edx, [esi + handler - callback_anchor]
    mov eax, [esi + IAT_VEH - callback_anchor]
    push edx
    push byte 1
    call [eax]
    test eax, eax
    jz short callback_exit

    pushfd
    xor eax, eax
    jz short junk_one_end
    db 0xE8, 0xFF, 0xFF
junk_one_end:
    popfd
    push eax
    mov eax, 0xA5A55A5A
    xor eax, 0xA5A55A5A
    test eax, eax
    jnz short bogus_stack_return
    pop eax
    test edx, edx
    jz short paired_end
    jnz short paired_end
    db 0xE8, 0x11, 0x22, 0x33, 0x44
paired_end:
    jmp short return_transfer
    db 0x0F, 0x0B, 0xEA, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xC2, 0x7C, 0x00

times 0x60-($-$$) db 0
callback_exit:
    push byte 0
    mov eax, [esi + IAT_EXIT - callback_anchor]
    call [eax]
    leave
    ret 12

times 0x70-($-$$) db 0
bogus_stack_return:
    add esp, byte 0x40
    ret 12
times 0x80-($-$$) db 0
callback_return:
    leave
    ret 12

return_transfer:
    call transfer_anchor
transfer_anchor:
    pop eax
    add eax, byte (stack_junk - transfer_anchor)
    push eax
    ret
    db 0xE8, 0xFF, 0xFF, 0xFF, 0x7F, 0xEA, 0xCC, 0xCC, 0xCC
stack_junk:
    pushfd
    push ecx
    mov ecx, esp
    sub esp, byte 0x20
    xor eax, eax
    rol eax, 1
    mov esp, ecx
    pop ecx
    popfd
    jmp short divide_setup
    db 0xE8, 0xFF, 0xFF, 0xFF, 0x7F, 0x0F, 0x0B, 0xC2, 0x7C, 0x00

times 0xC0-($-$$) db 0
divide_setup:
    mov eax, 1
    xor ecx, ecx
    cdq
divide_site:
    idiv ecx
    push byte 0
    mov eax, [esi + IAT_EXIT - callback_anchor]
    call [eax]
    int3

times 0x100-($-$$) db 0
handler:
    push ebp
    mov ebp, esp
    mov eax, [ebp+8]
    test eax, eax
    jz .decline
    mov ecx, [eax]
    test ecx, ecx
    jz .decline
    cmp dword [ecx], 0xC0000094
    jne .decline
    mov edx, [eax+4]
    test edx, edx
    jz .decline
    call .anchor
.anchor:
    pop eax
    sub eax, .anchor
    lea ecx, [eax+divide_site]
    cmp [edx+0xB8], ecx          ; Handle only our own intentional fault.
    jne .decline
    add eax, payload
    mov [edx+0xB8], eax
    mov eax, -1
    pop ebp
    ret 4
.decline:
    xor eax, eax
    pop ebp
    ret 4

times 0x200-($-$$) db 0
payload:
    push ebp
    mov ebp, esp
    sub esp, 0x80
    call .anchor
.anchor:
    pop esi
    sub esi, .anchor            ; ESI = base of global city.code.

    ; Decode numeric string data in memory once, before using Win32 APIs.
    lea edi, [esi+encoded_strings]
    mov ecx, encoded_strings_end-encoded_strings
    mov eax, STRING_SEED
.decode:
    mov edx, eax
    shl edx, 13
    xor eax, edx
    mov edx, eax
    shr edx, 17
    xor eax, edx
    mov edx, eax
    shl edx, 5
    xor eax, edx
    xor [edi], al
    inc edi
    dec ecx
    jnz .decode

    ; Open lowercase "flag" relative to the process working directory.
    push byte 0                ; hTemplateFile
    push dword 0x80            ; FILE_ATTRIBUTE_NORMAL
    push byte 3                ; OPEN_EXISTING
    push byte 0                ; security attributes
    push byte 1                ; FILE_SHARE_READ
    push dword 0x80000000       ; GENERIC_READ
    lea eax, [esi+file_name]
    push eax
    mov eax, [esi+IAT_CREATE]
    call [eax]
    cmp eax, -1
    je silent_exit
    mov [ebp-4], eax
    mov dword [ebp-8], 0

    ; One extra byte rejects longer files, including a trailing newline.
    push byte 0
    lea ecx, [ebp-8]
    push ecx
    push byte (FLAG_LENGTH+1)
    lea ecx, [ebp-0x70]
    push ecx
    push eax
    mov eax, [esi+IAT_READ]
    call [eax]
    mov [ebp-12], eax
    push dword [ebp-4]
    mov eax, [esi+IAT_CLOSE]
    call [eax]
    cmp dword [ebp-12], 0
    je silent_exit
    cmp dword [ebp-8], FLAG_LENGTH
    jne silent_exit

    lea edx, [ebp-0x70]
    mov edi, FLAG_LENGTH
    mov al, PAD_LENGTH
.pad:
    mov [edx+edi], al
    inc edi
    cmp edi, PADDED_LENGTH
    jb .pad

    lea edi, [ebp-0x70]
    lea ebx, [edi+PADDED_LENGTH]
    ; Compute the runtime return VA once; do not embed a fixed image address.
    lea edx, [esi+.block_done]
.block:
    ; Compute an indirect target from an encoded blob-relative offset.
    ; The real path executes 17 instructions including the final PUSH/JMP.
    pushfd
    push ecx
    xor ecx, ecx
    test ecx, ecx
    jnz short .transfer_bad_stack
    mov eax, (xtea_encrypt_block - $$) ^ XTEA_TRANSFER_MASK
    xor eax, XTEA_TRANSFER_MASK
    add eax, esi
    rol eax, 9
    ror eax, 9
    test edi, edi
    jz short .transfer_ready
    jnz short .transfer_ready
    db 0xE8, 0x11, 0x22, 0x33, 0x44
.transfer_bad_stack:
    add esp, byte 0x40
    ret
.transfer_ready:
    pop ecx
    popfd
    push edx
    jmp eax
.block_done:
    add edi, byte 8
    cmp edi, ebx
    jb .block

    ; Compare every ciphertext byte; the flag plaintext is not embedded.
    lea edi, [ebp-0x70]
    lea edx, [esi+expected_ciphertext]
    mov ecx, PADDED_LENGTH
    xor ebx, ebx
.compare:
    mov al, [edi]
    xor al, [edx]
    or bl, al
    inc edi
    inc edx
    dec ecx
    jnz .compare
    test ebx, ebx
    jnz silent_exit

    push byte 0x40             ; MB_OK | MB_ICONINFORMATION
    lea eax, [esi+message_title]
    push eax
    lea eax, [esi+message_text]
    push eax
    push byte 0
    mov eax, [esi+IAT_MSG]
    call [eax]
silent_exit:
    push byte 0
    mov eax, [esi+IAT_EXIT]
    call [eax]
    int3

; XTEA: 32 cycles (64 half-rounds), uint32 wraparound, little-endian words.
; EDI points to one 8-byte block. Preserve EBP/EBX/ESI/EDI for the caller.
; EDX contains the synthetic return address and is also preserved for reuse.
xtea_encrypt_block:
    ; The taken branch lands inside bytes that a linear decoder sees as CALL.
    pushfd
    xor eax, eax
    jz short .entry
    db 0xE8, 0xFF, 0xFF
.entry:
    popfd
    push ebp
    push ebx
    push edx

    ; The bad-stack path is unreachable at runtime, but is a false CFG edge.
    mov eax, 0x693CA55A
    xor eax, 0x693CA55A
    test eax, eax
    jnz .bad_stack_return
    mov ecx, esp
    sub esp, byte 0x20
    mov esp, ecx

    ; Complementary branches skip the same deliberately misleading bytes.
    test edi, edi
    jz short .setup
    jnz short .setup
    db 0xE8, 0x11, 0x22, 0x33, 0x44
.setup:
    mov ebx, [edi]
    mov edx, [edi+4]
    xor ebp, ebp
.round:
    mov eax, edx
    shl eax, 4
    mov ecx, edx
    shr ecx, 5
    xor eax, ecx
    add eax, edx
    mov ecx, ebp
    and ecx, byte 3
    mov ecx, [esi+ecx*4+xtea_key]
    add ecx, ebp
    xor eax, ecx
    add ebx, eax
    add ebp, 0x9E3779B9

    ; Balanced push/RET transfer between the two half-rounds; no CALL here.
    pushfd
    lea eax, [esi+.second_half]
    push eax
    ret
    db 0xE8, 0xFF, 0xFF, 0xFF, 0x7F, 0x0F, 0x0B
.second_half:
    popfd
    mov eax, ebx
    shl eax, 4
    mov ecx, ebx
    shr ecx, 5
    xor eax, ecx
    add eax, ebx
    mov ecx, ebp
    shr ecx, 11
    and ecx, byte 3
    mov ecx, [esi+ecx*4+xtea_key]
    add ecx, ebp
    xor eax, ecx
    add edx, eax
    cmp ebp, 0xC6EF3720
    jne .round
    mov [edi], ebx
    mov [edi+4], edx
    pop edx
    pop ebx
    pop ebp
    ret
.bad_stack_return:
    add esp, byte 0x40
    ret

times 0x800-($-$$) db 0
EMIT_CONSTANTS
times 0x1000-($-$$) db 0

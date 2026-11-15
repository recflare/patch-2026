; jjiEVn trampoline.
;
; The client passes its arguments straight through to the protector's jjiEVn
; (unknown arity, unknown types), so the machine state has to reach the
; protector untouched.
;
; That matters here: resolving the gate needs a C call, and a C call destroys
; the Windows x64 volatile argument registers (rax, rcx, rdx, r8-r11) and may
; touch xmm0-xmm5. Calling EnsureGate without saving them hands the protector
; a different argument list than the client built, which faults inside the
; protector rather than at the call site. So every volatile register is saved
; before the call and restored after it.
;
; The gate address is resolved lazily on the first call: the protector's
; export table only becomes usable once its unpack finishes.

        EXTERN g_realXNfn:QWORD
        EXTERN EnsureGate:PROC

        .code

jjiEVn PROC
        ; 0A8h keeps the stack 16-byte aligned at the call: entry rsp is
        ; 8 mod 16, and 0A8h is 8 mod 16, so rsp is 0 mod 16 before "call".
        sub     rsp, 0A8h

        mov     [rsp+00h], rax
        mov     [rsp+08h], rcx
        mov     [rsp+10h], rdx
        mov     [rsp+18h], r8
        mov     [rsp+20h], r9
        mov     [rsp+28h], r10
        mov     [rsp+30h], r11

        movaps  [rsp+40h], xmm0
        movaps  [rsp+50h], xmm1
        movaps  [rsp+60h], xmm2
        movaps  [rsp+70h], xmm3
        movaps  [rsp+80h], xmm4
        movaps  [rsp+90h], xmm5

        call    EnsureGate
        test    al, al
        jz      resolve_again

        movaps  xmm0, [rsp+40h]
        movaps  xmm1, [rsp+50h]
        movaps  xmm2, [rsp+60h]
        movaps  xmm3, [rsp+70h]
        movaps  xmm4, [rsp+80h]
        movaps  xmm5, [rsp+90h]

        mov     rax, [rsp+00h]
        mov     rcx, [rsp+08h]
        mov     rdx, [rsp+10h]
        mov     r8,  [rsp+18h]
        mov     r9,  [rsp+20h]
        mov     r10, [rsp+28h]
        mov     r11, [rsp+30h]

        add     rsp, 0A8h

        mov     rax, [g_realXNfn]
        jmp     rax

resolve_again:
        ; EnsureGate could not publish the gate yet. It logs the reason; try
        ; again rather than jumping to a null address.
        jmp     resolve_again
jjiEVn ENDP

        END

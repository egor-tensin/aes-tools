; Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
; This file is licensed under the terms of the MIT License.
; See LICENSE.txt for details.

.586
.xmm
.model flat

.data

align 10h
key_schedule oword 15 dup(0)

align 10h
inverse_key_schedule oword 15 dup(0)

.code

@raw_aes256cbc_encrypt@52 proc
    call expand_keys_256cbc
    pxor xmm0, [ecx]
    pxor xmm0, [key_schedule]
    aesenc xmm0, [key_schedule + 10h]
    aesenc xmm0, [key_schedule + 20h]
    aesenc xmm0, [key_schedule + 30h]
    aesenc xmm0, [key_schedule + 40h]
    aesenc xmm0, [key_schedule + 50h]
    aesenc xmm0, [key_schedule + 60h]
    aesenc xmm0, [key_schedule + 70h]
    aesenc xmm0, [key_schedule + 80h]
    aesenc xmm0, [key_schedule + 90h]
    aesenc xmm0, [key_schedule + 0A0h]
    aesenc xmm0, [key_schedule + 0B0h]
    aesenc xmm0, [key_schedule + 0C0h]
    aesenc xmm0, [key_schedule + 0D0h]
    aesenclast xmm0, [key_schedule + 0E0h]
    ret
@raw_aes256cbc_encrypt@52 endp

expand_keys_256cbc proc
    lea edx, [key_schedule + 20h]
    movdqa [key_schedule], xmm1
    movdqa [key_schedule + 10h], xmm2

    aeskeygenassist xmm7, xmm2, 1h
    pshufd xmm7, xmm7, 0FFh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 0
    pshufd xmm7, xmm7, 0AAh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 2h
    pshufd xmm7, xmm7, 0FFh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 0
    pshufd xmm7, xmm7, 0AAh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 4h
    pshufd xmm7, xmm7, 0FFh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 0
    pshufd xmm7, xmm7, 0AAh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 8h
    pshufd xmm7, xmm7, 0FFh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 0
    pshufd xmm7, xmm7, 0AAh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 10h
    pshufd xmm7, xmm7, 0FFh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 0
    pshufd xmm7, xmm7, 0AAh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 20h
    pshufd xmm7, xmm7, 0FFh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 0
    pshufd xmm7, xmm7, 0AAh
    call gen_round_key

    aeskeygenassist xmm7, xmm2, 40h
    pshufd xmm7, xmm7, 0FFh
    call gen_round_key

    call invert_key_schedule
    ret

gen_round_key:
    movdqa xmm6, xmm1

    pslldq xmm6, 4
    pxor xmm1, xmm6
    pslldq xmm6, 4
    pxor xmm1, xmm6
    pslldq xmm6, 4
    pxor xmm1, xmm6

    pxor xmm1, xmm7

    movdqa [edx], xmm1
    add edx, 10h

    movdqa xmm7, xmm1
    movdqa xmm1, xmm2
    movdqa xmm2, xmm7
    ret

invert_key_schedule:
    movdqa xmm7, [key_schedule]
    movdqa xmm6, [key_schedule + 0E0h]
    movdqa [inverse_key_schedule], xmm6
    movdqa [inverse_key_schedule + 0E0h], xmm7

    aesimc xmm7, [key_schedule + 10h]
    aesimc xmm6, [key_schedule + 0D0h]
    movdqa [inverse_key_schedule + 10h], xmm6
    movdqa [inverse_key_schedule + 0D0h], xmm7

    aesimc xmm7, [key_schedule + 20h]
    aesimc xmm6, [key_schedule + 0C0h]
    movdqa [inverse_key_schedule + 20h], xmm6
    movdqa [inverse_key_schedule + 0C0h], xmm7

    aesimc xmm7, [key_schedule + 30h]
    aesimc xmm6, [key_schedule + 0B0h]
    movdqa [inverse_key_schedule + 30h], xmm6
    movdqa [inverse_key_schedule + 0B0h], xmm7

    aesimc xmm7, [key_schedule + 40h]
    aesimc xmm6, [key_schedule + 0A0h]
    movdqa [inverse_key_schedule + 40h], xmm6
    movdqa [inverse_key_schedule + 0A0h], xmm7

    aesimc xmm7, [key_schedule + 50h]
    aesimc xmm6, [key_schedule + 90h]
    movdqa [inverse_key_schedule + 50h], xmm6
    movdqa [inverse_key_schedule + 90h], xmm7

    aesimc xmm7, [key_schedule + 60h]
    aesimc xmm6, [key_schedule + 80h]
    movdqa [inverse_key_schedule + 60h], xmm6
    movdqa [inverse_key_schedule + 80h], xmm7

    aesimc xmm7, [key_schedule + 70h]
    movdqa [inverse_key_schedule + 70h], xmm7

    ret
expand_keys_256cbc endp

@raw_aes256cbc_decrypt@52 proc
    call expand_keys_256cbc
    pxor xmm0, [inverse_key_schedule]
    aesdec xmm0, [inverse_key_schedule + 10h]
    aesdec xmm0, [inverse_key_schedule + 20h]
    aesdec xmm0, [inverse_key_schedule + 30h]
    aesdec xmm0, [inverse_key_schedule + 40h]
    aesdec xmm0, [inverse_key_schedule + 50h]
    aesdec xmm0, [inverse_key_schedule + 60h]
    aesdec xmm0, [inverse_key_schedule + 70h]
    aesdec xmm0, [inverse_key_schedule + 80h]
    aesdec xmm0, [inverse_key_schedule + 90h]
    aesdec xmm0, [inverse_key_schedule + 0A0h]
    aesdec xmm0, [inverse_key_schedule + 0B0h]
    aesdec xmm0, [inverse_key_schedule + 0C0h]
    aesdec xmm0, [inverse_key_schedule + 0D0h]
    aesdeclast xmm0, [inverse_key_schedule + 0E0h]
    pxor xmm0, [ecx]
    ret
@raw_aes256cbc_decrypt@52 endp

end

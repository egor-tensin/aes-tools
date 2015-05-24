; Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
; This file is licensed under the terms of the MIT License.
; See LICENSE.txt for details.

.586
.xmm
.model flat

.data

align 10h
key_schedule oword 11 dup(0)

align 10h
inverted_key_schedule oword 11 dup(0)

.code

@raw_aes128ecb_encrypt@32 proc
    call expand_keys_128ecb
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
    aesenclast xmm0, [key_schedule + 0A0h]
    ret
@raw_aes128ecb_encrypt@32 endp

@raw_aes128ecb_decrypt@32 proc
    call expand_keys_128ecb
    pxor xmm0, [inverted_key_schedule]
    aesdec xmm0, [inverted_key_schedule + 10h]
    aesdec xmm0, [inverted_key_schedule + 20h]
    aesdec xmm0, [inverted_key_schedule + 30h]
    aesdec xmm0, [inverted_key_schedule + 40h]
    aesdec xmm0, [inverted_key_schedule + 50h]
    aesdec xmm0, [inverted_key_schedule + 60h]
    aesdec xmm0, [inverted_key_schedule + 70h]
    aesdec xmm0, [inverted_key_schedule + 80h]
    aesdec xmm0, [inverted_key_schedule + 90h]
    aesdeclast xmm0, [inverted_key_schedule + 0A0h]
    ret
@raw_aes128ecb_decrypt@32 endp

expand_keys_128ecb proc
    lea ecx, [key_schedule + 10h]
    movdqa [key_schedule], xmm1

    aeskeygenassist xmm7, xmm1, 01h
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 02h
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 04h
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 08h
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 10h
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 20h
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 40h
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 80h
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 1Bh
    call gen_round_key
    aeskeygenassist xmm7, xmm1, 36h
    call gen_round_key

    call invert_key_schedule
    ret

gen_round_key:
    movdqa xmm6, xmm1    ; xmm6 = key_schedule[i]
                         ; xmm6 = x3 x2 x1 x0

    pslldq xmm6, 4     ; xmm6 = x2 x1 x0 0
    pxor xmm1, xmm6    ; xmm1 = (x3 x2) (x2 x1) (x1 x0) x0
    pslldq xmm6, 4     ; xmm6 = x1 x0 0 0
    pxor xmm1, xmm6    ; xmm1 = (x3 x2 x1) (x2 x1 x0) (x1 x0) x0
    pslldq xmm6, 4     ; xmm6 = x0 0 0 0
    pxor xmm1, xmm6    ; xmm1 = (x3 x2 x1 x0) (x2 x1 x0) (x1 x0) x0

    pshufd xmm7, xmm7, 0FFh
    pxor xmm1, xmm7

    movdqa [ecx], xmm1
    add ecx, 10h
    ret

invert_key_schedule:
    movdqa xmm7, [key_schedule]
    movdqa xmm6, [key_schedule + 0A0h]
    movdqa [inverted_key_schedule], xmm6
    movdqa [inverted_key_schedule + 0A0h], xmm7

    aesimc xmm7, [key_schedule + 10h]
    aesimc xmm6, [key_schedule + 90h]
    movdqa [inverted_key_schedule + 10h], xmm6
    movdqa [inverted_key_schedule + 90h], xmm7

    aesimc xmm7, [key_schedule + 20h]
    aesimc xmm6, [key_schedule + 80h]
    movdqa [inverted_key_schedule + 20h], xmm6
    movdqa [inverted_key_schedule + 80h], xmm7

    aesimc xmm7, [key_schedule + 30h]
    aesimc xmm6, [key_schedule + 70h]
    movdqa [inverted_key_schedule + 30h], xmm6
    movdqa [inverted_key_schedule + 70h], xmm7

    aesimc xmm7, [key_schedule + 40h]
    aesimc xmm6, [key_schedule + 60h]
    movdqa [inverted_key_schedule + 40h], xmm6
    movdqa [inverted_key_schedule + 60h], xmm7

    aesimc xmm7, [key_schedule + 50h]
    movdqa [inverted_key_schedule + 50h], xmm7

    ret
expand_keys_128ecb endp

end

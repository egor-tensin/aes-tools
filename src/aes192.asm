; Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
; This file is licensed under the terms of the MIT License.
; See LICENSE.txt for details.

.586
.xmm
.model flat

.data

align 10h
key_schedule oword 13 dup(0)

align 10h
inverted_key_schedule oword 13 dup(0)

.code

@aes192ecb_encrypt@48 proc
    call expand_keys_192ecb
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
    aesenclast xmm0, [key_schedule + 0C0h]
    ret
@aes192ecb_encrypt@48 endp

@aes192ecb_decrypt@48 proc
    call expand_keys_192ecb
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
    aesdec xmm0, [inverted_key_schedule + 0A0h]
    aesdec xmm0, [inverted_key_schedule + 0B0h]
    aesdeclast xmm0, [inverted_key_schedule + 0C0h]
    ret
@aes192ecb_decrypt@48 endp

expand_keys_192ecb proc
    ; key = k0 k1 k2 k3 k4 k5
    ; xmm1 = k0 k1 k2 k3
    ; xmm2 =  0  0 k5 k4

    ; w[0] = k0 k1 k2 k3
    ; w[1] = k4 k5  -  -

    ; i = 6
    ; while (i < 52):
    ;     temp = w[i - 1]
    ;     if (i % 6 == 0):
    ;         temp = SubWord(RotWord(w[i - 1])) * Rcon
    ;     w[i] = w[i - 6] * temp
    ;     i = i + 1

    ; w[6] = SubWord(RotWord(w[5])) * Rcon * w[0]
    ; w[7] = w[6] * w[1]
    ;      = SubWord(RotWord(w[5])) * Rcon * w[0] * w[1]
    ; w[8] = w[7] * w[2]
    ;      = SubWord(RotWord(w[5])) * Rcon * w[0] * w[1] * w[2]
    ; w[9] = w[8] * w[3]
    ;      = SubWord(RotWord(w[5])) * Rcon * w[0] * w[1] * w[2] * w[3]
    ; w[10] = w[9] * w[4]
    ;       = SubWord(RotWord(w[5])) * Rcon * w[0] * w[1] * w[2] * w[3] * w[4]
    ; w[11] = w[10] * w[5]
    ;       = SubWord(RotWord(w[5])) * Rcon * w[0] * w[1] * w[2] * w[3] * w[4] * w[5]

    movdqa [key_schedule], xmm1
    movdqa [key_schedule + 10h], xmm2

    lea ecx, [key_schedule + 18h]
    aeskeygenassist xmm7, xmm2, 1
    call gen_round_key
    aeskeygenassist xmm7, xmm2, 2
    call gen_round_key
    aeskeygenassist xmm7, xmm2, 4
    call gen_round_key
    aeskeygenassist xmm7, xmm2, 8
    call gen_round_key
    aeskeygenassist xmm7, xmm2, 10h
    call gen_round_key
    aeskeygenassist xmm7, xmm2, 20h
    call gen_round_key
    aeskeygenassist xmm7, xmm2, 40h
    call gen_round_key
    aeskeygenassist xmm7, xmm2, 80h
    call gen_round_key

    call invert_key_schedule
    ret

gen_round_key:
    ; xmm1 = x3 x2 x1 x0
    ; xmm2 =  -  - x5 x4
    ; xmm7 = RotWord(SubWord(-)) xor Rcon
    ;        SubWord(-)
    ;        RotWord(SubWord(x5)) xor Rcon
    ;        SubWord(x5)
    movdqa xmm6, xmm1

    pslldq xmm6, 4     ; xmm6 = x2 x1 x0 0
    pxor xmm1, xmm6    ; xmm1 = (x3 * x2) (x1 * x2) (x1 * x0) x0
    pslldq xmm6, 4     ; xmm6 = x1 x0 0 0
    pxor xmm1, xmm6    ; xmm1 = (x3 * x2 * x1) (x1 * x2 * x0) (x1 * x0) x0
    pslldq xmm6, 4     ; xmm6 = x0 0 0 0
    pxor xmm1, xmm6    ; xmm1 = (x3 * x2 * x1 * x0) (x1 * x2 * x0) (x1 * x0) x0

    pshufd xmm7, xmm7, 55h    ; xmm7 = RotWord(SubWord(x5)) * Rcon
                              ;        RotWord(SubWord(x5)) * Rcon
                              ;        RotWord(SubWord(x5)) * Rcon
                              ;        RotWord(SubWord(x5)) * Rcon

    pxor xmm1, xmm7    ; xmm1 = RotWord(SubWord(x5)) * Rcon * x3 * x2 * x1 * x0
                       ;        RotWord(SubWord(x5)) * Rcon * x2 * x1 * x0
                       ;        RotWord(SubWord(x5)) * Rcon * x1 * x0
                       ;        RotWord(SubWord(x5)) * Rcon * x0

    movq qword ptr [ecx], xmm1
    add ecx, 8

    pshufd xmm7, xmm1, 0FFh    ; xmm7 = -
                               ;        -
                               ;        RotWord(SubWord(x5)) * Rcon * x3 * x2 * x1 * x0
                               ;        RotWord(SubWord(x5)) * Rcon * x3 * x2 * x1 * x0
    pxor xmm7, xmm2           ; xmm7 = -
                              ;        -
                              ;        RotWord(SubWord(x5)) * Rcon * x5 * x3 * x2 * x1 * x0
                              ;        RotWord(SubWord(x5)) * Rcon * x4 * x3 * x2 * x1 * x0
    pslldq xmm2, 4            ; xmm2 = - k5 k4 0
    pxor xmm7, xmm2           ; xmm7 = -
                              ;        -
                              ;        RotWord(SubWord(x5)) * Rcon * x5 * x4 * x3 * x2 * x1 * x0
                              ;        RotWord(SubWord(x5)) * Rcon * x4 * x3 * x2 * x1 * x0

    movq xmm2, xmm7
    pslldq xmm7, 8
    movdqa xmm6, xmm1
    psrldq xmm6, 8
    por xmm7, xmm6
    movdqu [ecx], xmm7
    add ecx, 10h
    ret

invert_key_schedule:
    movdqa xmm7, [key_schedule]
    movdqa xmm6, [key_schedule + 0C0h]
    movdqa [inverted_key_schedule], xmm6
    movdqa [inverted_key_schedule + 0C0h], xmm7

    aesimc xmm7, [key_schedule + 10h]
    aesimc xmm6, [key_schedule + 0B0h]
    movdqa [inverted_key_schedule + 10h], xmm6
    movdqa [inverted_key_schedule + 0B0h], xmm7

    aesimc xmm7, [key_schedule + 20h]
    aesimc xmm6, [key_schedule + 0A0h]
    movdqa [inverted_key_schedule +  20h], xmm6
    movdqa [inverted_key_schedule + 0A0h], xmm7

    aesimc xmm7, [key_schedule + 30h]
    aesimc xmm6, [key_schedule + 90h]
    movdqa [inverted_key_schedule + 30h], xmm6
    movdqa [inverted_key_schedule + 90h], xmm7

    aesimc xmm7, [key_schedule + 40h]
    aesimc xmm6, [key_schedule + 80h]
    movdqa [inverted_key_schedule + 40h], xmm6
    movdqa [inverted_key_schedule + 80h], xmm7

    aesimc xmm7, [key_schedule + 50h]
    aesimc xmm6, [key_schedule + 70h]
    movdqa [inverted_key_schedule + 50h], xmm6
    movdqa [inverted_key_schedule + 70h], xmm7

    aesimc xmm7, [key_schedule + 60h]
    movdqa [inverted_key_schedule + 60h], xmm7
    
    ret
expand_keys_192ecb endp

end

; Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
; This file is licensed under the terms of the MIT License.
; See LICENSE.txt for details.

.586
.xmm
.model flat

.code

@raw_aes192ecb_encrypt@20 proc
    pxor xmm0, [ecx]
    aesenc xmm0, [ecx + 10h]
    aesenc xmm0, [ecx + 20h]
    aesenc xmm0, [ecx + 30h]
    aesenc xmm0, [ecx + 40h]
    aesenc xmm0, [ecx + 50h]
    aesenc xmm0, [ecx + 60h]
    aesenc xmm0, [ecx + 70h]
    aesenc xmm0, [ecx + 80h]
    aesenc xmm0, [ecx + 90h]
    aesenc xmm0, [ecx + 0A0h]
    aesenc xmm0, [ecx + 0B0h]
    aesenclast xmm0, [ecx + 0C0h]
    ret
@raw_aes192ecb_encrypt@20 endp

@raw_aes192cbc_encrypt@24 proc
    pxor xmm0, [edx]
    jmp @raw_aes192ecb_encrypt@20
@raw_aes192cbc_encrypt@24 endp

@raw_aes192ecb_decrypt@20 proc
    pxor xmm0, [ecx]
    aesdec xmm0, [ecx + 10h]
    aesdec xmm0, [ecx + 20h]
    aesdec xmm0, [ecx + 30h]
    aesdec xmm0, [ecx + 40h]
    aesdec xmm0, [ecx + 50h]
    aesdec xmm0, [ecx + 60h]
    aesdec xmm0, [ecx + 70h]
    aesdec xmm0, [ecx + 80h]
    aesdec xmm0, [ecx + 90h]
    aesdec xmm0, [ecx + 0A0h]
    aesdec xmm0, [ecx + 0B0h]
    aesdeclast xmm0, [ecx + 0C0h]
    ret
@raw_aes192ecb_decrypt@20 endp

@raw_aes192cbc_decrypt@24 proc
    call @raw_aes192ecb_decrypt@20
    pxor xmm0, [edx]
    ret
@raw_aes192cbc_decrypt@24 endp

@raw_aes192_expand_key_schedule@36 proc
    ; A "word" (in terms of the FIPS 187 standard) is a 32-bit block.
    ; Words are denoted by `w[N]`.
    ;
    ; A key schedule is composed of 12 "regular" keys and a dumb key for
    ; the "whitening" step.
    ;
    ; A key schedule is thus composed of 52 "words".
    ; The FIPS standard includes an algorithm to calculate these words via
    ; a simple loop:
    ;
    ; i = 6
    ; while i < 52:
    ;     temp = w[i - 1]
    ;     if i % 6 == 0:
    ;         temp = SubWord(RotWord(temp))^Rcon
    ;     w[i] = w[i - 6]^temp
    ;     i = i + 1
    ;
    ; The loop above may be unrolled like this:
    ;
    ; w[6] = SubWord(RotWord(w[5]))^Rcon^w[0]
    ; w[7] = w[6]^w[1]
    ;      = SubWord(RotWord(w[5]))^Rcon^w[0]^w[1]
    ; w[8] = w[7]^w[2]
    ;      = SubWord(RotWord(w[5]))^Rcon^w[0]^w[1]^w[2]
    ; w[9] = w[8]^w[3]
    ;      = SubWord(RotWord(w[5]))^Rcon^w[0]^w[1]^w[2]^w[3]
    ; w[10] = w[9]^w[4]
    ;       = SubWord(RotWord(w[5]))^Rcon^w[0]^w[1]^w[2]^w[3]^w[4]
    ; w[11] = w[10]^w[5]
    ;       = SubWord(RotWord(w[5]))^Rcon^w[0]^w[1]^w[2]^w[3]^w[4]^w[5]
    ; w[12] = SubWord(RotWord(w[11]))^Rcon^w[6]
    ; w[13] = w[12]^w[7]
    ;       = SubWord(RotWord(w[11]))^Rcon^w[6]^w[7]
    ; w[14] = w[13]^w[8]
    ;       = SubWord(RotWord(w[11]))^Rcon^w[6]^w[7]^w[8]
    ; w[15] = w[14]^w[9]
    ;       = SubWord(RotWord(w[11]))^Rcon^w[6]^w[7]^w[8]^w[9]
    ; w[16] = w[15]^w[10]
    ;       = SubWord(RotWord(w[11]))^Rcon^w[6]^w[7]^w[8]^w[9]^w[10]
    ; w[17] = w[16]^w[11]
    ;       = SubWort(RotWord(w[11]))^Rcon^w[6]^w[7]^w[8]^w[9]^w[10]^w[11]
    ;
    ; ... and so on.
    ;
    ; The Intel AES-NI instruction set facilitates calculating SubWord
    ; and RotWord using `aeskeygenassist`, which is used in this routine.
    ;
    ; Preconditions:
    ; * xmm1[63:32]  == w[5],
    ; * xmm1[31:0]   == w[4],
    ; * xmm0[127:96] == w[3],
    ; * xmm0[95:64]  == w[2],
    ; * xmm0[63:32]  == w[1],
    ; * xmm0[31:0]   == w[0].

    movdqa [ecx], xmm0          ; sets w[0], w[1], w[2], w[3]
    movdqa [ecx + 10h], xmm1    ; sets w[4], w[5]
    add ecx, 18h                ; ecx = &w[6]

    aeskeygenassist xmm7, xmm1, 1        ; xmm7[63:32] = RotWord(SubWord(w[5]))^Rcon,
    call gen_round_key                   ; sets w[6], w[7], w[8], w[9], w[10], w[11]
    aeskeygenassist xmm7, xmm1, 2        ; xmm7[63:32] = RotWord(SubWord(w[11]))^Rcon
    call gen_round_key                   ; sets w[12], w[13], w[14], w[15], w[16], w[17]
    aeskeygenassist xmm7, xmm1, 4        ; xmm7[63:32] = RotWord(SubWord(w[17]))^Rcon
    call gen_round_key                   ; sets w[18], w[19], w[20], w[21], w[22], w[23]
    aeskeygenassist xmm7, xmm1, 8        ; xmm7[63:32] = RotWord(SubWord(w[23]))^Rcon
    call gen_round_key                   ; sets w[24], w[25], w[26], w[27], w[28], w[29]
    aeskeygenassist xmm7, xmm1, 10h      ; xmm7[63:32] = RotWord(SubWord(w[29]))^Rcon
    call gen_round_key                   ; sets w[30], w[31], w[32], w[33], w[34], w[35]
    aeskeygenassist xmm7, xmm1, 20h      ; xmm7[63:32] = RotWord(SubWord(w[35]))^Rcon
    call gen_round_key                   ; sets w[36], w[37], w[38], w[39], w[40], w[41]
    aeskeygenassist xmm7, xmm1, 40h      ; xmm7[63:32] = RotWord(SubWord(w[41]))^Rcon
    call gen_round_key                   ; sets w[42], w[43], w[44], w[45], w[46], w[47]
    aeskeygenassist xmm7, xmm1, 80h      ; xmm7[63:32] = RotWord(SubWord(w[49]))^Rcon
    call gen_round_key                   ; sets w[48], w[49], w[50], w[51], w[52], w[53] // FIXME

    ret

gen_round_key:
    ; Preconditions:
    ; * xmm1[127:96] == 0,
    ; * xmm1[95:64]  == 0,
    ; * xmm1[63:32]  == w[i+5],
    ; * xmm1[31:0]   == w[i+4],
    ; * xmm0[127:96] == w[i+3],
    ; * xmm0[95:64]  == w[i+2],
    ; * xmm0[63:32]  == w[i+1],
    ; * xmm0[31:0]   == w[i],
    ; * xmm7[63:32]  == RotWord(SubWord(w[i+5]))^Rcon,
    ; * ecx == &w[i+6].
    ;
    ; Postconditions:
    ; * xmm1[127:96] == 0,
    ; * xmm1[95:64]  == 0,
    ; * xmm1[63:32]  == w[i+11] == RotWord(SubWord(w[i+5]))^Rcon^w[i+5]^w[i+4]^w[i+3]^w[i+2]^w[i+1]^w[i],
    ; * xmm1[31:0]   == w[i+10] == RotWord(SubWord(w[i+5]))^Rcon^w[i+4]^w[i+3]^w[i+2]^w[i+1]^w[i],
    ; * xmm0[127:96] == w[i+9]  == RotWord(SubWord(w[i+5]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i],
    ; * xmm0[95:64]  == w[i+8]  == RotWord(SubWord(w[i+5]))^Rcon^w[i+2]^w[i+1]^w[i],
    ; * xmm0[63:32]  == w[i+7]  == RotWord(SubWord(w[i+5]))^Rcon^w[i+1]^w[i],
    ; * xmm0[31:0]   == w[i+6]  == RotWord(SubWord(w[i+5]))^Rcon^w[i],
    ; * ecx == &w[i+12],
    ; * the value in xmm6 is also modified.

    ; Calculate
    ;     w[i+3]^w[i+2]^w[i+1]^w[i],
    ;     w[i+2]^w[i+1]^w[i],
    ;     w[i+1]^w[i] and
    ;     w[i].
    movdqa xmm6, xmm0    ; xmm6 = xmm0
    pslldq xmm6, 4       ; xmm6 <<= 32
    pxor xmm0, xmm6      ; xmm0 ^= xmm6
    pslldq xmm6, 4       ; xmm6 <<= 32
    pxor xmm0, xmm6      ; xmm0 ^= xmm6
    pslldq xmm6, 4       ; xmm6 <<= 32
    pxor xmm0, xmm6      ; xmm0 ^= xmm6
                         ; xmm0[127:96] == w[i+3]^w[i+2]^w[i+1]^w[i]
                         ; xmm0[95:64]  == w[i+2]^w[i+1]^w[i]
                         ; xmm0[63:32]  == w[i+1]^w[i]
                         ; xmm0[31:0]   == w[i]

    ; Calculate
    ;     w[i+9] == RotWord(SubWord(w[i+5]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i],
    ;     w[i+8] == RotWord(SubWord(w[i+5]))^Rcon^w[i+2]^w[i+1]^w[i],
    ;     w[i+7] == RotWord(SubWord(w[i+5]))^Rcon^w[i+1]^w[i] and
    ;     w[i+6] == RotWord(SubWord(w[i+5]))^Rcon^w[i].
    pshufd xmm6, xmm7, 55h    ; xmm6[127:96] = xmm6[95:64] = xmm6[63:32] = xmm6[31:0] = xmm7[63:32]
    pxor xmm0, xmm6           ; xmm0 ^= xmm6
                              ; xmm0[127:96] == w[i+9] == RotWord(SubWord(w[i+5]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i]
                              ; xmm0[95:64]  == w[i+8] == RotWord(SubWord(w[i+5]))^Rcon^w[i+2]^w[i+1]^w[i]
                              ; xmm0[63:32]  == w[i+7] == RotWord(SubWord(w[i+5]))^Rcon^w[i+1]^w[i]
                              ; xmm0[31:0]   == w[i+6] == RotWord(SubWord(w[i+5]))^Rcon^w[i]

    ; Set w[i+6], w[i+7], w[i+8] and w[i+9].
    movdqu [ecx], xmm0    ; w[i+6] = RotWord(SubWord(w[i+5]))^Rcon^w[i]
                          ; w[i+7] = RotWord(SubWord(w[i+5]))^Rcon^w[i+1]^w[i]
                          ; w[i+8] = RotWord(SubWord(w[i+5]))^Rcon^w[i+2]^w[i+1]^w[i]
                          ; w[i+9] = RotWord(SubWord(w[i+5]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i]
    add ecx, 10h          ; ecx = &w[i+10]

    ; Calculate
    ;     w[i+5]^w[i+4],
    ;     w[i+4].
    pshufd xmm6, xmm1, 0F3h    ; xmm6 = xmm1[31:0] << 32
    pxor xmm1, xmm6            ; xmm1 ^= xmm7
                               ; xmm1[63:32] == w[i+5]^w[i+4]
                               ; xmm1[31:0]  == w[i+4]

    ; Calculate
    ;     w[i+10] == RotWord(SubWord(w[i+5]))^Rcon^w[i+5]^w[i+4]^w[i+3]^w[i+2]^w[i+1]^w[i],
    ;     w[i+11] == RotWord(SubWord(w[i+5]))^Rcon^w[i+4]^w[i+3]^w[i+2]^w[i+1]^w[i].
    pshufd xmm6, xmm0, 0FFh    ; xmm6[127:96] = xmm6[95:64] = xmm6[63:32] = xmm6[31:0] = xmm0[127:96]
    psrldq xmm6, 8             ; xmm6 >>= 64
    pxor xmm1, xmm6            ; xmm1 ^= xmm6
                               ; xmm1[63:32] == w[i+11] == RotWord(SubWord(w[i+5]))^Rcon^w[i+5]^w[i+4]^w[i+3]^w[i+2]^w[i+1]^w[i]
                               ; xmm1[31:0]  == w[i+10] == RotWord(SubWord(w[i+5]))^Rcon^w[i+4]^w[i+3]^w[i+2]^w[i+1]^w[i]

    ; Set w[i+10] and w[i+11].
    movq qword ptr [ecx], xmm1    ; w[i+10] = RotWord(SubWord(w[i+5]))^Rcon^w[i+4]^w[i+3]^w[i+2]^w[i+1]^w[i]
                                  ; w[i+11] = RotWord(SubWord(w[i+5]))^Rcon^w[i+5]^w[i+4]^w[i+3]^w[i+2]^w[i+1]^w[i]
    add ecx, 8                    ; ecx = &w[i+12]

    ret
@raw_aes192_expand_key_schedule@36 endp

@raw_aes192_invert_key_schedule@8 proc
    movdqa xmm7, [ecx]
    movdqa xmm6, [ecx + 0C0h]
    movdqa [edx], xmm6
    movdqa [edx + 0C0h], xmm7

    aesimc xmm7, [ecx + 10h]
    aesimc xmm6, [ecx + 0B0h]
    movdqa [edx + 10h], xmm6
    movdqa [edx + 0B0h], xmm7

    aesimc xmm7, [ecx + 20h]
    aesimc xmm6, [ecx + 0A0h]
    movdqa [edx +  20h], xmm6
    movdqa [edx + 0A0h], xmm7

    aesimc xmm7, [ecx + 30h]
    aesimc xmm6, [ecx + 90h]
    movdqa [edx + 30h], xmm6
    movdqa [edx + 90h], xmm7

    aesimc xmm7, [ecx + 40h]
    aesimc xmm6, [ecx + 80h]
    movdqa [edx + 40h], xmm6
    movdqa [edx + 80h], xmm7

    aesimc xmm7, [ecx + 50h]
    aesimc xmm6, [ecx + 70h]
    movdqa [edx + 50h], xmm6
    movdqa [edx + 70h], xmm7

    aesimc xmm7, [ecx + 60h]
    movdqa [edx + 60h], xmm7

    ret
@raw_aes192_invert_key_schedule@8 endp

end

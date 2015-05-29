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

@raw_aes256ecb_encrypt@48 proc
    call expand_keys256
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
@raw_aes256ecb_encrypt@48 endp

@raw_aes256cbc_encrypt@52 proc
    pxor xmm0, [ecx]
    jmp @raw_aes256ecb_encrypt@48
@raw_aes256cbc_encrypt@52 endp

@raw_aes256ecb_decrypt@48 proc
    call expand_keys256
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
    ret
@raw_aes256ecb_decrypt@48 endp

@raw_aes256cbc_decrypt@52 proc
    push ecx
    call @raw_aes256ecb_decrypt@48
    pop ecx
    pxor xmm0, [ecx]
    ret
@raw_aes256cbc_decrypt@52 endp

expand_keys256 proc
    ; A "word" (in terms of the FIPS 187 standard) is a 32-bit block.
    ; Words are denoted by `w[N]`.
    ;
    ; A key schedule is composed of 14 "regular" keys and a dumb key for
    ; the "whitening" step.
    ; It's stored in `key_schedule`.
    ;
    ; A key schedule is thus composed of 60 "words".
    ; The FIPS standard includes an algorithm to calculate these words via
    ; a simple loop:
    ;
    ; i = 8
    ; while i < 60:
    ;     temp = w[i - 1]
    ;     if i % 8 == 0:
    ;         temp = SubWord(RotWord(temp))^Rcon
    ;     elif i % 8 == 4:
    ;         temp = SubWord(temp)
    ;     w[i] = w[i - 8]^temp
    ;     i = i + 1
    ;
    ; The loop above may be unrolled like this:
    ;
    ; w[8] = SubWord(RotWord(w[7]))^Rcon^w[0]
    ; w[9] = w[8]^w[1]
    ;      = SubWord(RotWord(w[7]))^Rcon^w[1]^w[0]
    ; w[10] = w[9]^w[2]
    ;       = SubWord(RotWord(w[7]))^Rcon^w[2]^w[1]^w[0]
    ; w[11] = w[10]^w[3]
    ;       = SubWord(RotWord(w[7]))^Rcon^w[3]^w[2]^w[1]^w[0]
    ; w[12] = SubWord(w[11])^w[4]
    ; w[13] = w[12]^w[5]
    ;       = SubWord(w[11])^w[5]^w[4]
    ; w[14] = w[13]^w[6]
    ;       = SubWord(w[11])^w[6]^w[5]^w[4]
    ; w[15] = w[14]^w[7]
    ;       = SubWord(w[11])^w[7]^w[6]^w[5]^w[4]
    ; w[16] = SubWord(RotWord(w[15]))^Rcon^w[8]
    ; w[17] = w[16]^w[9]
    ;       = SubWord(RotWord(w[15]))^Rcon^w[9]^w[8]
    ; w[18] = w[17]^w[10]
    ;       = SubWord(RotWord(w[15]))^Rcon^w[10]^w[9]^w[8]
    ; w[19] = w[18]^w[11]
    ;       = SubWord(RotWord(w[15]))^Rcon^w[11]^w[10]^w[9]^w[8]
    ; w[20] = SubWord(w[19])^w[12]
    ; w[21] = w[20]^w[13]
    ;       = SubWord(w[19])^w[13]^w[12]
    ; w[22] = w[21]^w[14]
    ;       = SubWord(w[19])^w[14]^w[13]^w[12]
    ; w[23] = w[22]^w[15]
    ;       = SubWord(w[19])^w[15]^w[14]^w[13]^w[12]
    ;
    ; ... and so on.
    ;
    ; The Intel AES-NI instruction set facilitates calculating SubWord
    ; and RotWord using `aeskeygenassist`, which is used in this routine.
    ;
    ; Preconditions:
    ; * xmm2[127:96] == w[7],
    ; * xmm2[95:64]  == w[6],
    ; * xmm2[63:32]  == w[5],
    ; * xmm2[31:0]   == w[4],
    ; * xmm1[127:96] == w[3],
    ; * xmm1[95:64]  == w[2],
    ; * xmm1[63:32]  == w[1],
    ; * xmm1[31:0]   == w[0].

    movdqa [key_schedule], xmm1          ; sets w[0], w[1], w[2], w[3]
    movdqa [key_schedule + 10h], xmm2    ; sets w[4], w[5], w[6], w[7]

    lea ecx, [key_schedule + 20h]        ; ecx = &w[8]

    aeskeygenassist xmm7, xmm2, 1h       ; xmm7[127:96] = RotWord(SubWord(w[7]))^Rcon
    pshufd xmm7, xmm7, 0FFh              ; xmm7[95:64] = xmm7[63:32] = xmm7[31:0] = xmm7[127:96]
    call gen_round_key                   ; sets w[8], w[9], w[10], w[11]

    aeskeygenassist xmm7, xmm2, 0        ; xmm7[95:64] = SubWord(w[11])
    pshufd xmm7, xmm7, 0AAh              ; xmm7[127:96] = xmm7[63:32] = xmm7[31:0] = xmm7[95:64]
    call gen_round_key                   ; sets w[12], w[13], w[14], w[15]

    aeskeygenassist xmm7, xmm2, 2h       ; xmm7[127:96] = RotWord(SubWord(w[15]))^Rcon
    pshufd xmm7, xmm7, 0FFh              ; xmm7[95:64] = xmm7[63:32] = xmm7[31:0] = xmm7[127:96]
    call gen_round_key                   ; sets w[16], w[17], w[18], w[19]

    aeskeygenassist xmm7, xmm2, 0        ; xmm7[95:64] = SubWord(w[19])
    pshufd xmm7, xmm7, 0AAh              ; xmm7[127:96] = xmm7[63:32] = xmm7[31:0] = xmm7[95:64]
    call gen_round_key                   ; sets w[20], w[21], w[22], w[23]

    aeskeygenassist xmm7, xmm2, 4h       ; xmm7[127:96] = RotWord(SubWord(w[23]))^Rcon
    pshufd xmm7, xmm7, 0FFh              ; xmm7[95:64] = xmm7[63:32] = xmm7[31:0] = xmm7[127:96]
    call gen_round_key                   ; sets w[24], w[25], w[26], w[27]

    aeskeygenassist xmm7, xmm2, 0        ; xmm7[95:64] = SubWord(w[27])
    pshufd xmm7, xmm7, 0AAh              ; xmm7[127:96] = xmm7[63:32] = xmm7[31:0] = xmm7[95:64]
    call gen_round_key                   ; sets w[28], w[29], w[30], w[31]

    aeskeygenassist xmm7, xmm2, 8h       ; xmm7[127:96] = RotWord(SubWord(w[31]))^Rcon
    pshufd xmm7, xmm7, 0FFh              ; xmm7[95:64] = xmm7[63:32] = xmm7[31:0] = xmm7[127:96]
    call gen_round_key                   ; sets w[32], w[33], w[34], w[35]

    aeskeygenassist xmm7, xmm2, 0        ; xmm7[95:64] = SubWord(w[35])
    pshufd xmm7, xmm7, 0AAh              ; xmm7[127:96] = xmm7[63:32] = xmm7[31:0] = xmm7[95:64]
    call gen_round_key                   ; sets w[36], w[37], w[38], w[39]

    aeskeygenassist xmm7, xmm2, 10h      ; xmm7[127:96] = RotWord(SubWord(w[39]))^Rcon
    pshufd xmm7, xmm7, 0FFh              ; xmm7[95:64] = xmm7[63:32] = xmm7[31:0] = xmm7[127:96]
    call gen_round_key                   ; sets w[40], w[41], w[42], w[43]

    aeskeygenassist xmm7, xmm2, 0        ; xmm7[95:64] = SubWord(w[43])
    pshufd xmm7, xmm7, 0AAh              ; xmm7[127:96] = xmm7[63:32] = xmm7[31:0] = xmm7[95:64]
    call gen_round_key                   ; sets w[44], w[45], w[46], w[47]

    aeskeygenassist xmm7, xmm2, 20h      ; xmm7[127:96] = RotWord(SubWord(w[47]))^Rcon
    pshufd xmm7, xmm7, 0FFh              ; xmm7[95:64] = xmm7[63:32] = xmm7[31:0] = xmm7[127:96]
    call gen_round_key                   ; sets w[48], w[49], w[50], w[51]

    aeskeygenassist xmm7, xmm2, 0        ; xmm7[95:64] = SubWord(w[51])
    pshufd xmm7, xmm7, 0AAh              ; xmm7[127:96] = xmm7[63:32] = xmm7[31:0] = xmm7[95:64]
    call gen_round_key                   ; sets w[52], w[53], w[54], w[55]

    aeskeygenassist xmm7, xmm2, 40h      ; xmm7[127:96] = RotWord(SubWord(w[55]))^Rcon
    pshufd xmm7, xmm7, 0FFh              ; xmm7[95:64] = xmm7[63:32] = xmm7[31:0] = xmm7[127:96]
    call gen_round_key                   ; sets w[56], w[57], w[58], w[59]

    call invert_key_schedule
    ret

gen_round_key:
    ; Preconditions:
    ; * xmm2[127:96] == w[i+7],
    ; * xmm2[95:64]  == w[i+6],
    ; * xmm2[63:32]  == w[i+5],
    ; * xmm2[31:0]   == w[i+4],
    ; * xmm1[127:96] == w[i+3],
    ; * xmm1[95:64]  == w[i+2],
    ; * xmm1[63:32]  == w[i+1],
    ; * xmm1[31:0]   == w[i],
    ; * xmm7[127:96] == xmm7[95:64] == xmm7[63:32] == xmm7[31:0] == HWGEN,
    ;   where HWGEN is either RotWord(SubWord(w[i+7]))^Rcon or SubWord(w[i+7]),
    ;   depending on the number of the round being processed,
    ; * ecx == &w[i+8].
    ;
    ; Postconditions:
    ; * xmm2[127:96] == w[i+11] == HWGEN^w[i+3]^w[i+2]^w[i+1]^w[i],
    ; * xmm2[95:64]  == w[i+10] == HWGEN^w[i+2]^w[i+1]^w[i],
    ; * xmm2[63:32]  == w[i+9]  == HWGEN^w[i+1]^w[i],
    ; * xmm2[31:0]   == w[i+8]  == HWGEN^w[i],
    ; * xmm1[127:96] == w[i+7],
    ; * xmm1[95:64]  == w[i+6],
    ; * xmm1[63:32]  == w[i+5],
    ; * xmm1[31:0]   == w[i+4],
    ; * ecx == &w[i+12],
    ; * the value in xmm6 is also modified.

    ; Calculate
    ;     w[i+3]^w[i+2]^w[i+1]^w[i],
    ;     w[i+2]^w[i+1]^w[i],
    ;     w[i+1]^w[i] and
    ;     w[i].
    movdqa xmm6, xmm1    ; xmm6 = xmm1
    pslldq xmm6, 4       ; xmm6 <<= 32
    pxor xmm1, xmm6      ; xmm1 ^= xmm6
    pslldq xmm6, 4       ; xmm6 <<= 32
    pxor xmm1, xmm6      ; xmm1 ^= xmm6
    pslldq xmm6, 4       ; xmm6 <<= 32
    pxor xmm1, xmm6      ; xmm1 ^= xmm6
                         ; xmm1[127:96] == w[i+3]^w[i+2]^w[i+1]^w[i]
                         ; xmm1[95:64]  == w[i+2]^w[i+1]^w[i]
                         ; xmm1[63:32]  == w[i+1]^w[i]
                         ; xmm1[31:0]   == w[i]

    ; Calculate
    ;     HWGEN^w[i+3]^w[i+2]^w[i+1]^w[i],
    ;     HWGEN^w[i+2]^w[i+1]^w[i],
    ;     HWGEN^w[i+1]^w[i] and
    ;     HWGEN^w[i].
    pxor xmm1, xmm7    ; xmm1 ^= xmm7
                       ; xmm1[127:96] == w[i+11] == HWGEN^w[i+3]^w[i+2]^w[i+1]^w[i]
                       ; xmm1[95:64]  == w[i+10] == HWGEN^w[i+2]^w[i+1]^w[i]
                       ; xmm1[63:32]  == w[i+9]  == HWGEN^w[i+1]^w[i]
                       ; xmm1[31:0]   == w[i+8]  == HWGEN^w[i]

    ; Set w[i+8], w[i+9], w[i+10] and w[i+11].
    movdqa [ecx], xmm1    ; w[i+8]  = HWGEN^w[i]
                          ; w[i+9]  = HWGEN^w[i+1]^w[i]
                          ; w[i+10] = HWGEN^w[i+2]^w[i+1]^w[i]
                          ; w[i+11] = HWGEN^w[i+3]^w[i+2]^w[i+1]^w[i]
    add ecx, 10h          ; ecx = &w[i+12]

    ; Swap the values in xmm1 and xmm2.
    pxor xmm1, xmm2
    pxor xmm2, xmm1
    pxor xmm1, xmm2

    ret

invert_key_schedule:
    movdqa xmm7, [key_schedule       ]
    movdqa xmm6, [key_schedule + 0E0h]
    movdqa [inverse_key_schedule       ], xmm6
    movdqa [inverse_key_schedule + 0E0h], xmm7

    aesimc xmm7, [key_schedule +  10h]
    aesimc xmm6, [key_schedule + 0D0h]
    movdqa [inverse_key_schedule +  10h], xmm6
    movdqa [inverse_key_schedule + 0D0h], xmm7

    aesimc xmm7, [key_schedule +  20h]
    aesimc xmm6, [key_schedule + 0C0h]
    movdqa [inverse_key_schedule +  20h], xmm6
    movdqa [inverse_key_schedule + 0C0h], xmm7

    aesimc xmm7, [key_schedule +  30h]
    aesimc xmm6, [key_schedule + 0B0h]
    movdqa [inverse_key_schedule +  30h], xmm6
    movdqa [inverse_key_schedule + 0B0h], xmm7

    aesimc xmm7, [key_schedule +  40h]
    aesimc xmm6, [key_schedule + 0A0h]
    movdqa [inverse_key_schedule +  40h], xmm6
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
expand_keys256 endp

end

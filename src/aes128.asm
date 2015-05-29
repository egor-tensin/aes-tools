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
    call expand_keys128
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

@raw_aes128cbc_encrypt@36 proc
    pxor xmm0, [ecx]
    jmp @raw_aes128ecb_encrypt@32
@raw_aes128cbc_encrypt@36 endp

@raw_aes128ecb_decrypt@32 proc
    call expand_keys128
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

@raw_aes128cbc_decrypt@36 proc
    push ecx
    call @raw_aes128ecb_decrypt@32
    pop ecx
    pxor xmm0, [ecx]
    ret
@raw_aes128cbc_decrypt@36 endp

expand_keys128 proc
    ; A "word" (in terms of the FIPS 187 standard) is a 32-bit block.
    ; Words are denoted by `w[N]`.
    ;
    ; A key schedule is composed of 10 "regular" keys and a dumb key for
    ; the "whitening" step.
    ; It's stored in `key_schedule`.
    ;
    ; A key schedule is thus composed of 44 "words".
    ; The FIPS standard includes an algorithm to calculate these words via
    ; a simple loop:
    ;
    ; i = 4
    ; while i < 44:
    ;     temp = w[i - 1]
    ;     if i % 4 == 0:
    ;         temp = SubWord(RotWord(temp))^Rcon
    ;     w[i] = w[i - 4]^temp
    ;     i = i + 1
    ;
    ; The loop above may be unrolled like this:
    ;
    ; w[4] = SubWord(RotWord(w[3]))^Rcon^w[0]
    ; w[5] = w[4]^w[1]
    ;      = SubWord(RotWord(w[3]))^Rcon^w[1]^w[0]
    ; w[6] = w[5]^w[2]
    ;      = SubWord(RotWord(w[3]))^Rcon^w[2]^w[1]^w[0]
    ; w[7] = w[6]^w[3]
    ;      = SubWord(RotWord(w[3]))^Rcon^w[3]^w[2]^w[1]^w[0]
    ; w[8] = SubWord(RotWord(w[7]))^Rcon^w[4]
    ; w[9] = w[8]^w[5]
    ;      = SubWord(RotWord(w[7]))^Rcon^w[5]^w[4]
    ; w[10] = w[9]^w[6]
    ;       = SubWord(RotWord(w[7]))^Rcon^w[6]^w[5]^w[4]
    ; w[11] = w[10]^w[7]
    ;       = SubWord(RotWord(w[7]))^Rcon^w[7]^w[6]^w[5]^w[4]
    ;
    ; ... and so on.
    ;
    ; The Intel AES-NI instruction set facilitates calculating SubWord
    ; and RotWord using `aeskeygenassist`, which is used in this routine.
    ;
    ; Preconditions:
    ; * xmm1[127:96] == w[3],
    ; * xmm1[95:64]  == w[2],
    ; * xmm1[63:32]  == w[1],
    ; * xmm1[31:0]   == w[0].

    movdqa [key_schedule], xmm1        ; sets w[0], w[1], w[2], w[3]

    lea ecx, [key_schedule + 10h]      ; ecx = &w[4]
    aeskeygenassist xmm7, xmm1, 01h    ; xmm7[127:96] = RotWord(SubWord(w[3]))^Rcon
    call gen_round_key                 ; sets w[4], w[5], w[6], w[7]
    aeskeygenassist xmm7, xmm1, 02h    ; xmm7[127:96] = RotWord(SubWord(w[7]))^Rcon
    call gen_round_key                 ; sets w[8], w[9], w[10], w[11]
    aeskeygenassist xmm7, xmm1, 04h    ; xmm7[127:96] = RotWord(SubWord(w[11]))^Rcon
    call gen_round_key                 ; sets w[12], w[13], w[14], w[15]
    aeskeygenassist xmm7, xmm1, 08h    ; xmm7[127:96] = RotWord(SubWord(w[15]))^Rcon
    call gen_round_key                 ; sets w[16], w[17], w[18], w[19]
    aeskeygenassist xmm7, xmm1, 10h    ; xmm7[127:96] = RotWord(SubWord(w[19]))^Rcon
    call gen_round_key                 ; sets w[20], w[21], w[22], w[23]
    aeskeygenassist xmm7, xmm1, 20h    ; xmm7[127:96] = RotWord(SubWord(w[23]))^Rcon
    call gen_round_key                 ; sets w[24], w[25], w[26], w[27]
    aeskeygenassist xmm7, xmm1, 40h    ; xmm7[127:96] = RotWord(SubWord(w[27]))^Rcon
    call gen_round_key                 ; sets w[28], w[29], w[30], w[31]
    aeskeygenassist xmm7, xmm1, 80h    ; xmm7[127:96] = RotWord(SubWord(w[31]))^Rcon
    call gen_round_key                 ; sets w[32], w[33], w[34], w[35]
    aeskeygenassist xmm7, xmm1, 1Bh    ; xmm7[127:96] = RotWord(SubWord(w[35]))^Rcon
    call gen_round_key                 ; sets w[36], w[37], w[38], w[39]
    aeskeygenassist xmm7, xmm1, 36h    ; xmm7[127:96] = RotWord(SubWord(w[39]))^Rcon
    call gen_round_key                 ; sets w[40], w[41], w[42], w[43]

    call invert_key_schedule
    ret

gen_round_key:
    ; Preconditions:
    ; * xmm1[127:96] == w[i+3],
    ; * xmm1[95:64]  == w[i+2],
    ; * xmm1[63:32]  == w[i+1],
    ; * xmm1[31:0]   == w[i],
    ; * xmm7[127:96] == RotWord(SubWord(w[i+3]))^Rcon,
    ; * ecx == &w[i+4].
    ;
    ; Postconditions:
    ; * xmm1[127:96] == w[i+7] == RotWord(SubWord(w[i+3]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i],
    ; * xmm1[95:64]  == w[i+6] == RotWord(SubWord(w[i+3]))^Rcon^w[i+2]^w[i+1]^w[i],
    ; * xmm1[63:32]  == w[i+5] == RotWord(SubWord(w[i+3]))^Rcon^w[i+1]^w[i],
    ; * xmm1[31:0]   == w[i+4] == RotWord(SubWord(w[i+3]))^Rcon^w[i],
    ; * ecx == &w[i+8],
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
    ;     w[i+7] == RotWord(SubWord(w[i+3]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i],
    ;     w[i+6] == RotWord(SubWord(w[i+3]))^Rcon^w[i+2]^w[i+1]^w[i],
    ;     w[i+5] == RotWord(SubWord(w[i+3]))^Rcon^w[i+1]^w[i] and
    ;     w[i+4] == RotWord(SubWord(w[i+3]))^Rcon^w[i].
    pshufd xmm6, xmm7, 0FFh    ; xmm6[127:96] = xmm6[95:64] = xmm6[63:32] = xmm6[31:0] = xmm7[127:96]
    pxor xmm1, xmm6            ; xmm1 ^= xmm6
                               ; xmm1[127:96] == w[i+7] == RotWord(SubWord(w[i+3]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i]
                               ; xmm1[95:64]  == w[i+6] == RotWord(SubWord(w[i+3]))^Rcon^w[i+2]^w[i+1]^w[i]
                               ; xmm1[63:32]  == w[i+5] == RotWord(SubWord(w[i+3]))^Rcon^w[i+1]^w[i]
                               ; xmm1[31:0]   == w[i+4] == RotWord(SubWord(w[i+3]))^Rcon^w[i]

    ; Set w[i+4], w[i+5], w[i+6] and w[i+7].
    movdqa [ecx], xmm1    ; w[i+7] = RotWord(SubWord(w[i+3]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i]
                          ; w[i+6] = RotWord(SubWord(w[i+3]))^Rcon^w[i+2]^w[i+1]^w[i]
                          ; w[i+5] = RotWord(SubWord(w[i+3]))^Rcon^w[i+1]^w[i]
                          ; w[i+4] = RotWord(SubWord(w[i+3]))^Rcon^w[i]
    add ecx, 10h          ; ecx = &w[i+8]

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
expand_keys128 endp

end

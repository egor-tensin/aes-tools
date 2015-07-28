; Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
; This file is licensed under the terms of the MIT License.
; See LICENSE.txt for details.

.586
.xmm
.model flat

.code

@aesni_AES128_encrypt_block_@20 proc
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
    aesenclast xmm0, [ecx + 0A0h]
    ret
@aesni_AES128_encrypt_block_@20 endp

@aesni_AES128_decrypt_block_@20 proc
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
    aesdeclast xmm0, [ecx + 0A0h]
    ret
@aesni_AES128_decrypt_block_@20 endp

@aesni_AES128_expand_key_@20 proc
    ; A "word" (in terms of the FIPS 187 standard) is a 32-bit block.
    ; Words are denoted by `w[N]`.
    ;
    ; A key schedule is composed of 10 "regular" keys and a dumb key for
    ; the "whitening" step.
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
    ; * xmm0[127:96] == w[3],
    ; * xmm0[95:64]  == w[2],
    ; * xmm0[63:32]  == w[1],
    ; * xmm0[31:0]   == w[0].

    movdqa [ecx], xmm0    ; sets w[0], w[1], w[2], w[3]
    add ecx, 10h          ; ecx = &w[4]

    aeskeygenassist xmm5, xmm0, 01h    ; xmm5[127:96] = RotWord(SubWord(w[3]))^Rcon
    call aes128_keygen_assist          ; sets w[4], w[5], w[6], w[7]
    aeskeygenassist xmm5, xmm0, 02h    ; xmm5[127:96] = RotWord(SubWord(w[7]))^Rcon
    call aes128_keygen_assist          ; sets w[8], w[9], w[10], w[11]
    aeskeygenassist xmm5, xmm0, 04h    ; xmm5[127:96] = RotWord(SubWord(w[11]))^Rcon
    call aes128_keygen_assist          ; sets w[12], w[13], w[14], w[15]
    aeskeygenassist xmm5, xmm0, 08h    ; xmm5[127:96] = RotWord(SubWord(w[15]))^Rcon
    call aes128_keygen_assist          ; sets w[16], w[17], w[18], w[19]
    aeskeygenassist xmm5, xmm0, 10h    ; xmm5[127:96] = RotWord(SubWord(w[19]))^Rcon
    call aes128_keygen_assist          ; sets w[20], w[21], w[22], w[23]
    aeskeygenassist xmm5, xmm0, 20h    ; xmm5[127:96] = RotWord(SubWord(w[23]))^Rcon
    call aes128_keygen_assist          ; sets w[24], w[25], w[26], w[27]
    aeskeygenassist xmm5, xmm0, 40h    ; xmm5[127:96] = RotWord(SubWord(w[27]))^Rcon
    call aes128_keygen_assist          ; sets w[28], w[29], w[30], w[31]
    aeskeygenassist xmm5, xmm0, 80h    ; xmm5[127:96] = RotWord(SubWord(w[31]))^Rcon
    call aes128_keygen_assist          ; sets w[32], w[33], w[34], w[35]
    aeskeygenassist xmm5, xmm0, 1Bh    ; xmm5[127:96] = RotWord(SubWord(w[35]))^Rcon
    call aes128_keygen_assist          ; sets w[36], w[37], w[38], w[39]
    aeskeygenassist xmm5, xmm0, 36h    ; xmm5[127:96] = RotWord(SubWord(w[39]))^Rcon
    call aes128_keygen_assist          ; sets w[40], w[41], w[42], w[43]

    ret

aes128_keygen_assist:
    ; Preconditions:
    ; * xmm0[127:96] == w[i+3],
    ; * xmm0[95:64]  == w[i+2],
    ; * xmm0[63:32]  == w[i+1],
    ; * xmm0[31:0]   == w[i],
    ; * xmm5[127:96] == RotWord(SubWord(w[i+3]))^Rcon,
    ; * ecx == &w[i+4].
    ;
    ; Postconditions:
    ; * xmm0[127:96] == w[i+7] == RotWord(SubWord(w[i+3]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i],
    ; * xmm0[95:64]  == w[i+6] == RotWord(SubWord(w[i+3]))^Rcon^w[i+2]^w[i+1]^w[i],
    ; * xmm0[63:32]  == w[i+5] == RotWord(SubWord(w[i+3]))^Rcon^w[i+1]^w[i],
    ; * xmm0[31:0]   == w[i+4] == RotWord(SubWord(w[i+3]))^Rcon^w[i],
    ; * ecx == &w[i+8],
    ; * the value in xmm4 is also modified.

    ; Calculate
    ;     w[i+3]^w[i+2]^w[i+1]^w[i],
    ;     w[i+2]^w[i+1]^w[i],
    ;     w[i+1]^w[i] and
    ;     w[i].
    movdqa xmm4, xmm0    ; xmm4 = xmm0
    pslldq xmm4, 4       ; xmm4 <<= 32
    pxor xmm0, xmm4      ; xmm0 ^= xmm4
    pslldq xmm4, 4       ; xmm4 <<= 32
    pxor xmm0, xmm4      ; xmm0 ^= xmm4
    pslldq xmm4, 4       ; xmm4 <<= 32
    pxor xmm0, xmm4      ; xmm0 ^= xmm4
                         ; xmm0[127:96] == w[i+3]^w[i+2]^w[i+1]^w[i]
                         ; xmm0[95:64]  == w[i+2]^w[i+1]^w[i]
                         ; xmm0[63:32]  == w[i+1]^w[i]
                         ; xmm0[31:0]   == w[i]

    ; Calculate
    ;     w[i+7] == RotWord(SubWord(w[i+3]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i],
    ;     w[i+6] == RotWord(SubWord(w[i+3]))^Rcon^w[i+2]^w[i+1]^w[i],
    ;     w[i+5] == RotWord(SubWord(w[i+3]))^Rcon^w[i+1]^w[i] and
    ;     w[i+4] == RotWord(SubWord(w[i+3]))^Rcon^w[i].
    pshufd xmm4, xmm5, 0FFh    ; xmm4[127:96] = xmm4[95:64] = xmm4[63:32] = xmm4[31:0] = xmm5[127:96]
    pxor xmm0, xmm4            ; xmm0 ^= xmm4
                               ; xmm0[127:96] == w[i+7] == RotWord(SubWord(w[i+3]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i]
                               ; xmm0[95:64]  == w[i+6] == RotWord(SubWord(w[i+3]))^Rcon^w[i+2]^w[i+1]^w[i]
                               ; xmm0[63:32]  == w[i+5] == RotWord(SubWord(w[i+3]))^Rcon^w[i+1]^w[i]
                               ; xmm0[31:0]   == w[i+4] == RotWord(SubWord(w[i+3]))^Rcon^w[i]

    ; Set w[i+4], w[i+5], w[i+6] and w[i+7].
    movdqa [ecx], xmm0    ; w[i+7] = RotWord(SubWord(w[i+3]))^Rcon^w[i+3]^w[i+2]^w[i+1]^w[i]
                          ; w[i+6] = RotWord(SubWord(w[i+3]))^Rcon^w[i+2]^w[i+1]^w[i]
                          ; w[i+5] = RotWord(SubWord(w[i+3]))^Rcon^w[i+1]^w[i]
                          ; w[i+4] = RotWord(SubWord(w[i+3]))^Rcon^w[i]
    add ecx, 10h          ; ecx = &w[i+8]

    ret
@aesni_AES128_expand_key_@20 endp

@aesni_AES128_derive_decryption_keys_@8 proc
    movdqa xmm5, [ecx]
    movdqa xmm4, [ecx + 0A0h]
    movdqa [edx], xmm4
    movdqa [edx + 0A0h], xmm5

    aesimc xmm5, [ecx + 10h]
    aesimc xmm4, [ecx + 90h]
    movdqa [edx + 10h], xmm4
    movdqa [edx + 90h], xmm5

    aesimc xmm5, [ecx + 20h]
    aesimc xmm4, [ecx + 80h]
    movdqa [edx + 20h], xmm4
    movdqa [edx + 80h], xmm5

    aesimc xmm5, [ecx + 30h]
    aesimc xmm4, [ecx + 70h]
    movdqa [edx + 30h], xmm4
    movdqa [edx + 70h], xmm5

    aesimc xmm5, [ecx + 40h]
    aesimc xmm4, [ecx + 60h]
    movdqa [edx + 40h], xmm4
    movdqa [edx + 60h], xmm5

    aesimc xmm5, [ecx + 50h]
    movdqa [edx + 50h], xmm5

    ret
@aesni_AES128_derive_decryption_keys_@8 endp

end

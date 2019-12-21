/*
 * Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <emmintrin.h>
#include <wmmintrin.h>

AES_AES_Block __fastcall aes_AES128_encrypt_block_(
    AES_AES_Block plaintext,
    const AES_AES128_RoundKeys* encryption_keys)
{
    plaintext = _mm_xor_si128(plaintext, encryption_keys->keys[0]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[1]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[2]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[3]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[4]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[5]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[6]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[7]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[8]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[9]);
    return _mm_aesenclast_si128(plaintext, encryption_keys->keys[10]);
}

AES_AES_Block __fastcall aes_AES128_decrypt_block_(
    AES_AES_Block ciphertext,
    const AES_AES128_RoundKeys* decryption_keys)
{
    ciphertext = _mm_xor_si128(ciphertext, decryption_keys->keys[0]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[1]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[2]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[3]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[4]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[5]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[6]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[7]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[8]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[9]);
    return _mm_aesdeclast_si128(ciphertext, decryption_keys->keys[10]);
}

static AES_AES_Block __fastcall aes_aes128_expand_key_assist(
    AES_AES_Block prev,
    AES_AES_Block hwgen)
{
    AES_AES_Block tmp = prev;

    tmp = _mm_slli_si128(tmp, 4);
    prev = _mm_xor_si128(prev, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    prev = _mm_xor_si128(prev, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    prev = _mm_xor_si128(prev, tmp);

    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    prev = _mm_xor_si128(prev, hwgen);

    return prev;
}

void __fastcall aes_AES128_expand_key_(
    AES_AES_Block key,
    AES_AES128_RoundKeys* encryption_keys)
{
    AES_Block128 prev = encryption_keys->keys[0] = key;
    prev = encryption_keys->keys[1] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x01));
    prev = encryption_keys->keys[2] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x02));
    prev = encryption_keys->keys[3] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x04));
    prev = encryption_keys->keys[4] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x08));
    prev = encryption_keys->keys[5] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x10));
    prev = encryption_keys->keys[6] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x20));
    prev = encryption_keys->keys[7] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x40));
    prev = encryption_keys->keys[8] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x80));
    prev = encryption_keys->keys[9] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x1b));
    prev = encryption_keys->keys[10] = aes_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x36));
}

void __fastcall aes_AES128_derive_decryption_keys_(
    const AES_AES128_RoundKeys* encryption_keys,
    AES_AES128_RoundKeys* decryption_keys)
{
    decryption_keys->keys[0] = encryption_keys->keys[10];
    decryption_keys->keys[1] = _mm_aesimc_si128(encryption_keys->keys[9]);
    decryption_keys->keys[2] = _mm_aesimc_si128(encryption_keys->keys[8]);
    decryption_keys->keys[3] = _mm_aesimc_si128(encryption_keys->keys[7]);
    decryption_keys->keys[4] = _mm_aesimc_si128(encryption_keys->keys[6]);
    decryption_keys->keys[5] = _mm_aesimc_si128(encryption_keys->keys[5]);
    decryption_keys->keys[6] = _mm_aesimc_si128(encryption_keys->keys[4]);
    decryption_keys->keys[7] = _mm_aesimc_si128(encryption_keys->keys[3]);
    decryption_keys->keys[8] = _mm_aesimc_si128(encryption_keys->keys[2]);
    decryption_keys->keys[9] = _mm_aesimc_si128(encryption_keys->keys[1]);
    decryption_keys->keys[10] = encryption_keys->keys[0];
}

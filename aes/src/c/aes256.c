/*
 * Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <emmintrin.h>
#include <wmmintrin.h>

AES_AES_Block __fastcall aes_AES256_encrypt_block_(
    AES_AES_Block plaintext,
    const AES_AES256_RoundKeys* encryption_keys)
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
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[10]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[11]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[12]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[13]);
    return _mm_aesenclast_si128(plaintext, encryption_keys->keys[14]);
}

AES_AES_Block __fastcall aes_AES256_decrypt_block_(
    AES_AES_Block ciphertext,
    const AES_AES256_RoundKeys* decryption_keys)
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
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[10]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[11]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[12]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[13]);
    return _mm_aesdeclast_si128(ciphertext, decryption_keys->keys[14]);
}

static AES_AES_Block __fastcall aes_aes256_expand_key_assist(
    AES_AES_Block* prev_lo,
    AES_AES_Block* prev_hi,
    AES_AES_Block hwgen)
{
    AES_AES_Block tmp = *prev_lo;

    tmp = _mm_slli_si128(tmp, 4);
    *prev_lo = _mm_xor_si128(*prev_lo, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    *prev_lo = _mm_xor_si128(*prev_lo, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    *prev_lo = _mm_xor_si128(*prev_lo, tmp);

    *prev_lo = _mm_xor_si128(*prev_lo, hwgen);

    *prev_hi = _mm_xor_si128(*prev_hi, *prev_lo);
    *prev_lo = _mm_xor_si128(*prev_lo, *prev_hi);
    *prev_hi = _mm_xor_si128(*prev_hi, *prev_lo);

    return *prev_hi;
}

void __fastcall aes_AES256_expand_key_(
    AES_AES_Block key_lo,
    AES_AES_Block key_hi,
    AES_AES256_RoundKeys* encryption_keys)
{
    AES_AES_Block prev_lo, prev_hi;
    AES_AES_Block hwgen;

    prev_lo = encryption_keys->keys[0] = key_lo;
    prev_hi = encryption_keys->keys[1] = key_hi;

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x01);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    encryption_keys->keys[2] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    encryption_keys->keys[3] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x02);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    encryption_keys->keys[4] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    encryption_keys->keys[5] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x04);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    encryption_keys->keys[6] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    encryption_keys->keys[7] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x08);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    encryption_keys->keys[8] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    encryption_keys->keys[9] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x10);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    encryption_keys->keys[10] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    encryption_keys->keys[11] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x20);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    encryption_keys->keys[12] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    encryption_keys->keys[13] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x40);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    encryption_keys->keys[14] = aes_aes256_expand_key_assist(&prev_lo, &prev_hi, hwgen);
}

void __fastcall aes_AES256_derive_decryption_keys_(
    const AES_AES256_RoundKeys* encryption_keys,
    AES_AES256_RoundKeys* decryption_keys)
{
    decryption_keys->keys[0] = encryption_keys->keys[14];
    decryption_keys->keys[1] = _mm_aesimc_si128(encryption_keys->keys[13]);
    decryption_keys->keys[2] = _mm_aesimc_si128(encryption_keys->keys[12]);
    decryption_keys->keys[3] = _mm_aesimc_si128(encryption_keys->keys[11]);
    decryption_keys->keys[4] = _mm_aesimc_si128(encryption_keys->keys[10]);
    decryption_keys->keys[5] = _mm_aesimc_si128(encryption_keys->keys[9]);
    decryption_keys->keys[6] = _mm_aesimc_si128(encryption_keys->keys[8]);
    decryption_keys->keys[7] = _mm_aesimc_si128(encryption_keys->keys[7]);
    decryption_keys->keys[8] = _mm_aesimc_si128(encryption_keys->keys[6]);
    decryption_keys->keys[9] = _mm_aesimc_si128(encryption_keys->keys[5]);
    decryption_keys->keys[10] = _mm_aesimc_si128(encryption_keys->keys[4]);
    decryption_keys->keys[11] = _mm_aesimc_si128(encryption_keys->keys[3]);
    decryption_keys->keys[12] = _mm_aesimc_si128(encryption_keys->keys[2]);
    decryption_keys->keys[13] = _mm_aesimc_si128(encryption_keys->keys[1]);
    decryption_keys->keys[14] = encryption_keys->keys[0];
}

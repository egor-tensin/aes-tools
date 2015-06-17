/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <emmintrin.h>
#include <wmmintrin.h>

AesNI_Aes_Block __fastcall aesni_aes192_encrypt_block_(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys)
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
    return _mm_aesenclast_si128(plaintext, encryption_keys->keys[12]);
}

AesNI_Aes_Block __fastcall aesni_aes192_decrypt_block_(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes192_RoundKeys* decryption_keys)
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
    return _mm_aesdeclast_si128(ciphertext, decryption_keys->keys[12]);
}

static void __fastcall aesni_aes192_expand_key_assist(
    AesNI_Aes_Block* prev_lo,
    AesNI_Aes_Block* prev_hi,
    AesNI_Aes_Block hwgen)
{
    AesNI_Aes_Block tmp = *prev_lo;

    tmp = _mm_slli_si128(tmp, 4);
    *prev_lo = _mm_xor_si128(*prev_lo, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    *prev_lo = _mm_xor_si128(*prev_lo, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    *prev_lo = _mm_xor_si128(*prev_lo, tmp);

    hwgen = _mm_shuffle_epi32(hwgen, 0x55);
    *prev_lo = _mm_xor_si128(*prev_lo, hwgen);

    tmp = _mm_shuffle_epi32(*prev_hi, 0xf3);
    *prev_hi = _mm_xor_si128(*prev_hi, tmp);

    tmp = _mm_shuffle_epi32(*prev_lo, 0xff);
    tmp = _mm_srli_si128(tmp, 8);
    *prev_hi = _mm_xor_si128(*prev_hi, tmp);
}

void __fastcall aesni_aes192_expand_key_(
    AesNI_Aes_Block key_lo,
    AesNI_Aes_Block key_hi,
    AesNI_Aes192_RoundKeys* encryption_keys)
{
    encryption_keys->keys[0] = key_lo;
    encryption_keys->keys[1] = key_hi;

    aesni_aes192_expand_key_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x01));
    encryption_keys->keys[1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(encryption_keys->keys[1]), _mm_castsi128_pd(key_lo), 0));
    encryption_keys->keys[2] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_lo), _mm_castsi128_pd(key_hi), 1));

    aesni_aes192_expand_key_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x02));
    encryption_keys->keys[3] = key_lo;
    encryption_keys->keys[4] = key_hi;

    aesni_aes192_expand_key_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x04));
    encryption_keys->keys[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(encryption_keys->keys[4]), _mm_castsi128_pd(key_lo), 0));
    encryption_keys->keys[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_lo), _mm_castsi128_pd(key_hi), 1));

    aesni_aes192_expand_key_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x08));
    encryption_keys->keys[6] = key_lo;
    encryption_keys->keys[7] = key_hi;

    aesni_aes192_expand_key_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x10));
    encryption_keys->keys[7] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(encryption_keys->keys[7]), _mm_castsi128_pd(key_lo), 0));
    encryption_keys->keys[8] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_lo), _mm_castsi128_pd(key_hi), 1));

    aesni_aes192_expand_key_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x20));
    encryption_keys->keys[9] = key_lo;
    encryption_keys->keys[10] = key_hi;

    aesni_aes192_expand_key_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x40));
    encryption_keys->keys[10] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(encryption_keys->keys[10]), _mm_castsi128_pd(key_lo), 0));
    encryption_keys->keys[11] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_lo), _mm_castsi128_pd(key_hi), 1));

    aesni_aes192_expand_key_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x80));
    encryption_keys->keys[12] = key_lo;
}

void __fastcall aesni_aes192_derive_decryption_keys_(
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes192_RoundKeys* decryption_keys)
{
    decryption_keys->keys[0] = encryption_keys->keys[12];
    decryption_keys->keys[1] = _mm_aesimc_si128(encryption_keys->keys[11]);
    decryption_keys->keys[2] = _mm_aesimc_si128(encryption_keys->keys[10]);
    decryption_keys->keys[3] = _mm_aesimc_si128(encryption_keys->keys[9]);
    decryption_keys->keys[4] = _mm_aesimc_si128(encryption_keys->keys[8]);
    decryption_keys->keys[5] = _mm_aesimc_si128(encryption_keys->keys[7]);
    decryption_keys->keys[6] = _mm_aesimc_si128(encryption_keys->keys[6]);
    decryption_keys->keys[7] = _mm_aesimc_si128(encryption_keys->keys[5]);
    decryption_keys->keys[8] = _mm_aesimc_si128(encryption_keys->keys[4]);
    decryption_keys->keys[9] = _mm_aesimc_si128(encryption_keys->keys[3]);
    decryption_keys->keys[10] = _mm_aesimc_si128(encryption_keys->keys[2]);
    decryption_keys->keys[11] = _mm_aesimc_si128(encryption_keys->keys[1]);
    decryption_keys->keys[12] = encryption_keys->keys[0];
}

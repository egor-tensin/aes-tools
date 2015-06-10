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

AesNI_Block128 __fastcall aesni_raw_encrypt_block256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule)
{
    plain = _mm_xor_si128(plain, key_schedule->keys[0]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[1]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[2]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[3]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[4]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[5]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[6]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[7]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[8]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[9]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[10]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[11]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[12]);
    plain = _mm_aesenc_si128(plain, key_schedule->keys[13]);
    return _mm_aesenclast_si128(plain, key_schedule->keys[14]);
}

AesNI_Block128 __fastcall aesni_raw_decrypt_block256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* inverted_schedule)
{
    cipher = _mm_xor_si128(cipher, inverted_schedule->keys[0]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[1]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[2]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[3]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[4]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[5]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[6]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[7]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[8]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[9]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[10]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[11]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[12]);
    cipher = _mm_aesdec_si128(cipher, inverted_schedule->keys[13]);
    return _mm_aesdeclast_si128(cipher, inverted_schedule->keys[14]);
}

static AesNI_Block128 __fastcall aes256_keygen_assist(
    AesNI_Block128* prev_lo,
    AesNI_Block128* prev_hi,
    AesNI_Block128 hwgen)
{
    AesNI_Block128 tmp = *prev_lo;

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

void __fastcall aesni_raw_expand_key_schedule256(
    AesNI_Block128 key_lo,
    AesNI_Block128 key_hi,
    AesNI_KeySchedule256* key_schedule)
{
    AesNI_Block128 prev_lo, prev_hi;
    AesNI_Block128 hwgen;

    prev_lo = key_schedule->keys[0] = key_lo;
    prev_hi = key_schedule->keys[1] = key_hi;

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x01);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    key_schedule->keys[2] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    key_schedule->keys[3] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x02);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    key_schedule->keys[4] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    key_schedule->keys[5] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x04);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    key_schedule->keys[6] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    key_schedule->keys[7] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x08);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    key_schedule->keys[8] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    key_schedule->keys[9] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x10);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    key_schedule->keys[10] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    key_schedule->keys[11] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x20);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    key_schedule->keys[12] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0);
    hwgen = _mm_shuffle_epi32(hwgen, 0xaa);
    key_schedule->keys[13] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);

    hwgen = _mm_aeskeygenassist_si128(prev_hi, 0x40);
    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    key_schedule->keys[14] = aes256_keygen_assist(&prev_lo, &prev_hi, hwgen);
}

void __fastcall aesni_raw_invert_key_schedule256(
    AesNI_KeySchedule256* key_schedule,
    AesNI_KeySchedule256* inverted_schedule)
{
    inverted_schedule->keys[0] = key_schedule->keys[14];
    inverted_schedule->keys[1] = _mm_aesimc_si128(key_schedule->keys[13]);
    inverted_schedule->keys[2] = _mm_aesimc_si128(key_schedule->keys[12]);
    inverted_schedule->keys[3] = _mm_aesimc_si128(key_schedule->keys[11]);
    inverted_schedule->keys[4] = _mm_aesimc_si128(key_schedule->keys[10]);
    inverted_schedule->keys[5] = _mm_aesimc_si128(key_schedule->keys[9]);
    inverted_schedule->keys[6] = _mm_aesimc_si128(key_schedule->keys[8]);
    inverted_schedule->keys[7] = _mm_aesimc_si128(key_schedule->keys[7]);
    inverted_schedule->keys[8] = _mm_aesimc_si128(key_schedule->keys[6]);
    inverted_schedule->keys[9] = _mm_aesimc_si128(key_schedule->keys[5]);
    inverted_schedule->keys[10] = _mm_aesimc_si128(key_schedule->keys[4]);
    inverted_schedule->keys[11] = _mm_aesimc_si128(key_schedule->keys[3]);
    inverted_schedule->keys[12] = _mm_aesimc_si128(key_schedule->keys[2]);
    inverted_schedule->keys[13] = _mm_aesimc_si128(key_schedule->keys[1]);
    inverted_schedule->keys[14] = key_schedule->keys[0];
}

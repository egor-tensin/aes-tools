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

AesBlock128 __fastcall raw_aes192_encrypt(
    AesBlock128 plain,
    Aes192KeySchedule* key_schedule)
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
    return _mm_aesenclast_si128(plain, key_schedule->keys[12]);
}

AesBlock128 __fastcall raw_aes192_decrypt(
    AesBlock128 cipher,
    Aes192KeySchedule* inverted_schedule)
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
    return _mm_aesdeclast_si128(cipher, inverted_schedule->keys[12]);
}

static void __fastcall aes192_keygen_assist(
    AesBlock128* prev_lo,
    AesBlock128* prev_hi,
    AesBlock128 hwgen)
{
    AesBlock128 tmp = *prev_lo;

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

void __fastcall raw_aes192_expand_key_schedule(
    AesBlock128 key_lo,
    AesBlock128 key_hi,
    Aes192KeySchedule* key_schedule)
{
    key_schedule->keys[0] = key_lo;
    key_schedule->keys[1] = key_hi;

    aes192_keygen_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x01));
    key_schedule->keys[1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_schedule->keys[1]), _mm_castsi128_pd(key_lo), 0));
    key_schedule->keys[2] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_lo), _mm_castsi128_pd(key_hi), 1));

    aes192_keygen_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x02));
    key_schedule->keys[3] = key_lo;
    key_schedule->keys[4] = key_hi;

    aes192_keygen_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x04));
    key_schedule->keys[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_schedule->keys[4]), _mm_castsi128_pd(key_lo), 0));
    key_schedule->keys[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_lo), _mm_castsi128_pd(key_hi), 1));

    aes192_keygen_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x08));
    key_schedule->keys[6] = key_lo;
    key_schedule->keys[7] = key_hi;

    aes192_keygen_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x10));
    key_schedule->keys[7] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_schedule->keys[7]), _mm_castsi128_pd(key_lo), 0));
    key_schedule->keys[8] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_lo), _mm_castsi128_pd(key_hi), 1));

    aes192_keygen_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x20));
    key_schedule->keys[9] = key_lo;
    key_schedule->keys[10] = key_hi;

    aes192_keygen_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x40));
    key_schedule->keys[10] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_schedule->keys[10]), _mm_castsi128_pd(key_lo), 0));
    key_schedule->keys[11] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(key_lo), _mm_castsi128_pd(key_hi), 1));

    aes192_keygen_assist(&key_lo, &key_hi, _mm_aeskeygenassist_si128(key_hi, 0x80));
    key_schedule->keys[12] = key_lo;
}

void __fastcall raw_aes192_invert_key_schedule(
    Aes192KeySchedule* key_schedule,
    Aes192KeySchedule* inverted_schedule)
{
    inverted_schedule->keys[0] = key_schedule->keys[12];
    inverted_schedule->keys[1] = _mm_aesimc_si128(key_schedule->keys[11]);
    inverted_schedule->keys[2] = _mm_aesimc_si128(key_schedule->keys[10]);
    inverted_schedule->keys[3] = _mm_aesimc_si128(key_schedule->keys[9]);
    inverted_schedule->keys[4] = _mm_aesimc_si128(key_schedule->keys[8]);
    inverted_schedule->keys[5] = _mm_aesimc_si128(key_schedule->keys[7]);
    inverted_schedule->keys[6] = _mm_aesimc_si128(key_schedule->keys[6]);
    inverted_schedule->keys[7] = _mm_aesimc_si128(key_schedule->keys[5]);
    inverted_schedule->keys[8] = _mm_aesimc_si128(key_schedule->keys[4]);
    inverted_schedule->keys[9] = _mm_aesimc_si128(key_schedule->keys[3]);
    inverted_schedule->keys[10] = _mm_aesimc_si128(key_schedule->keys[2]);
    inverted_schedule->keys[11] = _mm_aesimc_si128(key_schedule->keys[1]);
    inverted_schedule->keys[12] = key_schedule->keys[0];
}

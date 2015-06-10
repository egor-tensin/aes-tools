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

AesBlock128 __fastcall raw_aes128_encrypt_block(
    AesBlock128 plain,
    Aes128KeySchedule* key_schedule)
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
    return _mm_aesenclast_si128(plain, key_schedule->keys[10]);
}

AesBlock128 __fastcall raw_aes128_decrypt_block(
    AesBlock128 cipher,
    Aes128KeySchedule* inverted_schedule)
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
    return _mm_aesdeclast_si128(cipher, inverted_schedule->keys[10]);
}

static AesBlock128 __fastcall aes128_keygen_assist(
    AesBlock128 prev,
    AesBlock128 hwgen)
{
    AesBlock128 tmp = prev;

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

void __fastcall raw_aes128_expand_key_schedule(
    AesBlock128 key,
    Aes128KeySchedule* key_schedule)
{
    AesBlock128 prev = key_schedule->keys[0] = key;
    prev = key_schedule->keys[1] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x01));
    prev = key_schedule->keys[2] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x02));
    prev = key_schedule->keys[3] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x04));
    prev = key_schedule->keys[4] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x08));
    prev = key_schedule->keys[5] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x10));
    prev = key_schedule->keys[6] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x20));
    prev = key_schedule->keys[7] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x40));
    prev = key_schedule->keys[8] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x80));
    prev = key_schedule->keys[9] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x1b));
    prev = key_schedule->keys[10] = aes128_keygen_assist(prev, _mm_aeskeygenassist_si128(prev, 0x36));
}

void __fastcall raw_aes128_invert_key_schedule(
    Aes128KeySchedule* key_schedule,
    Aes128KeySchedule* inverted_schedule)
{
    inverted_schedule->keys[0] = key_schedule->keys[10];
    inverted_schedule->keys[1] = _mm_aesimc_si128(key_schedule->keys[9]);
    inverted_schedule->keys[2] = _mm_aesimc_si128(key_schedule->keys[8]);
    inverted_schedule->keys[3] = _mm_aesimc_si128(key_schedule->keys[7]);
    inverted_schedule->keys[4] = _mm_aesimc_si128(key_schedule->keys[6]);
    inverted_schedule->keys[5] = _mm_aesimc_si128(key_schedule->keys[5]);
    inverted_schedule->keys[6] = _mm_aesimc_si128(key_schedule->keys[4]);
    inverted_schedule->keys[7] = _mm_aesimc_si128(key_schedule->keys[3]);
    inverted_schedule->keys[8] = _mm_aesimc_si128(key_schedule->keys[2]);
    inverted_schedule->keys[9] = _mm_aesimc_si128(key_schedule->keys[1]);
    inverted_schedule->keys[10] = key_schedule->keys[0];
}

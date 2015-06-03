/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "data.h"
#include "raw.h"

static __inline void __fastcall aes128_expand_key_schedule(
    AesBlock128 key,
    Aes128KeySchedule* key_schedule)
{
    raw_aes128_expand_key_schedule(key, key_schedule);
}

static __inline void __fastcall aes128_invert_key_schedule(
    Aes128KeySchedule* key_schedule,
    Aes128KeySchedule* inverted_schedule)
{
    raw_aes128_invert_key_schedule(key_schedule, inverted_schedule);
}

static __inline AesBlock128 __fastcall aes128ecb_encrypt(
    AesBlock128 plain,
    Aes128KeySchedule* key_schedule)
{
    return raw_aes128ecb_encrypt(plain, key_schedule);
}

static __inline AesBlock128 __fastcall aes128ecb_decrypt(
    AesBlock128 cypher,
    Aes128KeySchedule* inverted_schedule)
{
    return raw_aes128ecb_decrypt(cypher, inverted_schedule);
}

static __inline AesBlock128 __fastcall aes128cbc_encrypt(
    AesBlock128 plain,
    Aes128KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 cypher = raw_aes128ecb_encrypt(_mm_xor_si128(plain, init_vector), key_schedule);
    _mm_storeu_si128(next_init_vector, cypher);
    return cypher;
}

static __inline AesBlock128 __fastcall aes128cbc_decrypt(
    AesBlock128 cypher,
    Aes128KeySchedule* inverted_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 plain = _mm_xor_si128(raw_aes128ecb_decrypt(cypher, inverted_schedule), init_vector);
    _mm_storeu_si128(next_init_vector, cypher);
    return plain;
}

static __inline AesBlock128 __fastcall aes128cfb_encrypt(
    AesBlock128 plain,
    Aes128KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 cypher = _mm_xor_si128(raw_aes128ecb_encrypt(init_vector, key_schedule), plain);
    _mm_storeu_si128(next_init_vector, cypher);
    return cypher;
}

static __inline AesBlock128 __fastcall aes128cfb_decrypt(
    AesBlock128 cypher,
    Aes128KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 plain = _mm_xor_si128(raw_aes128ecb_encrypt(init_vector, key_schedule), cypher);
    _mm_storeu_si128(next_init_vector, cypher);
    return plain;
}

static __inline AesBlock128 __fastcall aes128ofb_encrypt(
    AesBlock128 plain,
    Aes128KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 tmp = raw_aes128ecb_encrypt(init_vector, key_schedule);
    _mm_storeu_si128(next_init_vector, tmp);
    return _mm_xor_si128(tmp, plain);
}

static __inline AesBlock128 __fastcall aes128ofb_decrypt(
    AesBlock128 cypher,
    Aes128KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 tmp = raw_aes128ecb_encrypt(init_vector, key_schedule);
    _mm_storeu_si128(next_init_vector, tmp);
    return _mm_xor_si128(tmp, cypher);
}

static __inline void __fastcall aes192_expand_key_schedule(
    AesBlock192* key,
    Aes192KeySchedule* key_schedule)
{
    raw_aes192_expand_key_schedule(key->lo, key->hi, key_schedule);
}

static __inline void __fastcall aes192_invert_key_schedule(
    Aes192KeySchedule* key_schedule,
    Aes192KeySchedule* inverted_schedule)
{
    raw_aes192_invert_key_schedule(key_schedule, inverted_schedule);
}

static __inline AesBlock128 __fastcall aes192ecb_encrypt(
    AesBlock128 plain,
    Aes192KeySchedule* key_schedule)
{
    return raw_aes192ecb_encrypt(plain, key_schedule);
}

static __inline AesBlock128 __fastcall aes192ecb_decrypt(
    AesBlock128 cypher,
    Aes192KeySchedule* inverted_schedule)
{
    return raw_aes192ecb_decrypt(cypher, inverted_schedule);
}

static __inline AesBlock128 __fastcall aes192cbc_encrypt(
    AesBlock128 plain,
    Aes192KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 cypher = raw_aes192ecb_encrypt(_mm_xor_si128(plain, init_vector), key_schedule);
    _mm_storeu_si128(next_init_vector, cypher);
    return cypher;
}

static __inline AesBlock128 __fastcall aes192cbc_decrypt(
    AesBlock128 cypher,
    Aes192KeySchedule* inverted_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 plain = _mm_xor_si128(raw_aes192ecb_decrypt(cypher, inverted_schedule), init_vector);
    _mm_storeu_si128(next_init_vector, cypher);
    return plain;
}

static __inline AesBlock128 __fastcall aes192cfb_encrypt(
    AesBlock128 plain,
    Aes192KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 cypher = _mm_xor_si128(raw_aes192ecb_encrypt(init_vector, key_schedule), plain);
    _mm_storeu_si128(next_init_vector, cypher);
    return cypher;
}

static __inline AesBlock128 __fastcall aes192cfb_decrypt(
    AesBlock128 cypher,
    Aes192KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 plain = _mm_xor_si128(raw_aes192ecb_encrypt(init_vector, key_schedule), cypher);
    _mm_storeu_si128(next_init_vector, cypher);
    return plain;
}

static __inline AesBlock128 __fastcall aes192ofb_encrypt(
    AesBlock128 plain,
    Aes192KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 tmp = raw_aes192ecb_encrypt(init_vector, key_schedule);
    _mm_storeu_si128(next_init_vector, tmp);
    return _mm_xor_si128(tmp, plain);
}

static __inline AesBlock128 __fastcall aes192ofb_decrypt(
    AesBlock128 cypher,
    Aes192KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 tmp = raw_aes192ecb_encrypt(init_vector, key_schedule);
    _mm_storeu_si128(next_init_vector, tmp);
    return _mm_xor_si128(tmp, cypher);
}

static __inline void __fastcall aes256_expand_key_schedule(
    AesBlock256* key,
    Aes256KeySchedule* key_schedule)
{
    raw_aes256_expand_key_schedule(key->lo, key->hi, key_schedule);
}

static __inline void __fastcall aes256_invert_key_schedule(
    Aes256KeySchedule* key_schedule,
    Aes256KeySchedule* inverted_schedule)
{
    raw_aes256_invert_key_schedule(key_schedule, inverted_schedule);
}

static __inline AesBlock128 __fastcall aes256ecb_encrypt(
    AesBlock128 plain,
    Aes256KeySchedule* key_schedule)
{
    return raw_aes256ecb_encrypt(plain, key_schedule);
}

static __inline AesBlock128 __fastcall aes256ecb_decrypt(
    AesBlock128 cypher,
    Aes256KeySchedule* inverted_schedule)
{
    return raw_aes256ecb_decrypt(cypher, inverted_schedule);
}

static __inline AesBlock128 __fastcall aes256cbc_encrypt(
    AesBlock128 plain,
    Aes256KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 cypher = raw_aes256ecb_encrypt(_mm_xor_si128(plain, init_vector), key_schedule);
    _mm_storeu_si128(next_init_vector, cypher);
    return cypher;
}

static __inline AesBlock128 __fastcall aes256cbc_decrypt(
    AesBlock128 cypher,
    Aes256KeySchedule* inverted_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 plain = _mm_xor_si128(raw_aes256ecb_decrypt(cypher, inverted_schedule), init_vector);
    _mm_storeu_si128(next_init_vector, cypher);
    return plain;
}

static __inline AesBlock128 __fastcall aes256cfb_encrypt(
    AesBlock128 plain,
    Aes256KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 cypher = _mm_xor_si128(raw_aes256ecb_encrypt(init_vector, key_schedule), plain);
    _mm_storeu_si128(next_init_vector, cypher);
    return cypher;
}

static __inline AesBlock128 __fastcall aes256cfb_decrypt(
    AesBlock128 cypher,
    Aes256KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 plain = _mm_xor_si128(raw_aes256ecb_encrypt(init_vector, key_schedule), cypher);
    _mm_storeu_si128(next_init_vector, cypher);
    return plain;
}

static __inline AesBlock128 __fastcall aes256ofb_encrypt(
    AesBlock128 plain,
    Aes256KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 tmp = raw_aes256ecb_encrypt(init_vector, key_schedule);
    _mm_storeu_si128(next_init_vector, tmp);
    return _mm_xor_si128(tmp, plain);
}

static __inline AesBlock128 __fastcall aes256ofb_decrypt(
    AesBlock128 cypher,
    Aes256KeySchedule* key_schedule,
    AesBlock128 init_vector,
    AesBlock128* next_init_vector)
{
    AesBlock128 tmp = raw_aes256ecb_encrypt(init_vector, key_schedule);
    _mm_storeu_si128(next_init_vector, tmp);
    return _mm_xor_si128(tmp, cypher);
}

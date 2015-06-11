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

#include <assert.h>

#ifdef __cplusplus
extern "C"
{
#endif

static __inline void __fastcall aesni_expand_key_schedule128(
    AesNI_Block128 key,
    AesNI_KeySchedule128* key_schedule)
{
    assert(key_schedule);

    aesni_raw_expand_key_schedule128(key, key_schedule);
}

static __inline void __fastcall aesni_invert_key_schedule128(
    AesNI_KeySchedule128* key_schedule,
    AesNI_KeySchedule128* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_raw_invert_key_schedule128(key_schedule, inverted_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ecb128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule)
{
    assert(key_schedule);

    return aesni_raw_encrypt_block128(plain, key_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ecb128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_raw_decrypt_block128(cipher, inverted_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cbc128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_raw_encrypt_block128(_mm_xor_si128(plain, init_vector), key_schedule);
    *next_init_vector = cipher;
    return cipher;
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cbc128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(aesni_raw_decrypt_block128(cipher, inverted_schedule), init_vector);
    *next_init_vector = cipher;
    return plain;
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cfb128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = _mm_xor_si128(aesni_raw_encrypt_block128(init_vector, key_schedule), plain);
    *next_init_vector = cipher;
    return cipher;
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cfb128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(aesni_raw_encrypt_block128(init_vector, key_schedule), cipher);
    *next_init_vector = cipher;
    return plain;
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ofb128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block128(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, plain);
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ofb128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block128(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, cipher);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ctr128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);
    return _mm_xor_si128(plain, aesni_raw_encrypt_block128(init_vector, key_schedule));
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ctr128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);
    return _mm_xor_si128(cipher, aesni_raw_encrypt_block128(init_vector, key_schedule));
}

static __inline void __fastcall aesni_expand_key_schedule192(
    AesNI_Block192* key,
    AesNI_KeySchedule192* key_schedule)
{
    assert(key);
    assert(key_schedule);

    aesni_raw_expand_key_schedule192(key->lo, key->hi, key_schedule);
}

static __inline void __fastcall aesni_invert_key_schedule192(
    AesNI_KeySchedule192* key_schedule,
    AesNI_KeySchedule192* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_raw_invert_key_schedule192(key_schedule, inverted_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ecb192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule)
{
    assert(key_schedule);

    return aesni_raw_encrypt_block192(plain, key_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ecb192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_raw_decrypt_block192(cipher, inverted_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cbc192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_raw_encrypt_block192(_mm_xor_si128(plain, init_vector), key_schedule);
    *next_init_vector = cipher;
    return cipher;
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cbc192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(aesni_raw_decrypt_block192(cipher, inverted_schedule), init_vector);
    *next_init_vector = cipher;
    return plain;
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cfb192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = _mm_xor_si128(aesni_raw_encrypt_block192(init_vector, key_schedule), plain);
    *next_init_vector = cipher;
    return cipher;
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cfb192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(aesni_raw_encrypt_block192(init_vector, key_schedule), cipher);
    *next_init_vector = cipher;
    return plain;
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ofb192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block192(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, plain);
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ofb192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block192(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, cipher);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ctr192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);
    return _mm_xor_si128(plain, aesni_raw_encrypt_block192(init_vector, key_schedule));
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ctr192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);
    return _mm_xor_si128(cipher, aesni_raw_encrypt_block192(init_vector, key_schedule));
}

static __inline void __fastcall aesni_expand_key_schedule256(
    AesNI_Block256* key,
    AesNI_KeySchedule256* key_schedule)
{
    assert(key);
    assert(key_schedule);

    aesni_raw_expand_key_schedule256(key->lo, key->hi, key_schedule);
}

static __inline void __fastcall aesni_invert_key_schedule256(
    AesNI_KeySchedule256* key_schedule,
    AesNI_KeySchedule256* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_raw_invert_key_schedule256(key_schedule, inverted_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ecb256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule)
{
    assert(key_schedule);

    return aesni_raw_encrypt_block256(plain, key_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ecb256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_raw_decrypt_block256(cipher, inverted_schedule);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cbc256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_raw_encrypt_block256(_mm_xor_si128(plain, init_vector), key_schedule);
    *next_init_vector = cipher;
    return cipher;
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cbc256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(aesni_raw_decrypt_block256(cipher, inverted_schedule), init_vector);
    *next_init_vector = cipher;
    return plain;
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cfb256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = _mm_xor_si128(aesni_raw_encrypt_block256(init_vector, key_schedule), plain);
    *next_init_vector = cipher;
    return cipher;
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cfb256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(aesni_raw_encrypt_block256(init_vector, key_schedule), cipher);
    *next_init_vector = cipher;
    return plain;
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ofb256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block256(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, plain);
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ofb256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block256(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, cipher);
}

static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ctr256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);
    return _mm_xor_si128(plain, aesni_raw_encrypt_block256(init_vector, key_schedule));
}

static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ctr256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);
    return _mm_xor_si128(cipher, aesni_raw_encrypt_block256(init_vector, key_schedule));
}

#ifdef __cplusplus
}
#endif

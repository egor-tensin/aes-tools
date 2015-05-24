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

static __inline AesBlock128 __fastcall aes128ecb_encrypt(
    AesBlock128 plain,
    AesBlock128 key)
{
    return raw_aes128ecb_encrypt(plain, key);
}

static __inline AesBlock128 __fastcall aes128ecb_decrypt(
    AesBlock128 cypher,
    AesBlock128 key)
{
    return raw_aes128ecb_decrypt(cypher, key);
}

static __inline AesBlock128 __fastcall aes192ecb_encrypt(
    AesBlock128 plain,
    AesBlock192* key)
{
    return raw_aes192ecb_encrypt(plain, key->lo, key->hi);
}

static __inline AesBlock128 __fastcall aes192ecb_decrypt(
    AesBlock128 cypher,
    AesBlock192* key)
{
    return raw_aes192ecb_decrypt(cypher, key->lo, key->hi);
}

static __inline AesBlock128 __fastcall aes256ecb_encrypt(
    AesBlock128 plain,
    AesBlock256* key)
{
    return raw_aes256ecb_encrypt(plain, key->lo, key->hi);
}

static __inline AesBlock128 __fastcall aes256ecb_decrypt(
    AesBlock128 cypher,
    AesBlock256* key)
{
    return raw_aes256ecb_decrypt(cypher, key->lo, key->hi);
}

static __inline AesBlock128 __fastcall aes256cbc_encrypt(
    AesBlock128 plain,
    AesBlock256* key,
    AesBlock128* initialization_vector)
{
    return raw_aes256cbc_encrypt(plain, key->lo, key->hi, initialization_vector);
}

static __inline AesBlock128 __fastcall aes256cbc_decrypt(
    AesBlock128 cypher,
    AesBlock256* key,
    AesBlock128* initialization_vector)
{
    return raw_aes256cbc_decrypt(cypher, key->lo, key->hi, initialization_vector);
}

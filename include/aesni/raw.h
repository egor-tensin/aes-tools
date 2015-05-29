/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "data.h"

AesBlock128 __fastcall raw_aes128ecb_encrypt(
    AesBlock128 plain,
    AesBlock128 key);
AesBlock128 __fastcall raw_aes128ecb_decrypt(
    AesBlock128 cypher,
    AesBlock128 key);

AesBlock128 __fastcall raw_aes128cbc_encrypt(
    AesBlock128 plain,
    AesBlock128 key,
    AesBlock128* iv);
AesBlock128 __fastcall raw_aes128cbc_decrypt(
    AesBlock128 cypher,
    AesBlock128 key,
    AesBlock128* iv);

AesBlock128 __fastcall raw_aes192ecb_encrypt(
    AesBlock128 plain,
    AesBlock128 key_lo,
    AesBlock128 key_hi);
AesBlock128 __fastcall raw_aes192ecb_decrypt(
    AesBlock128 cypher,
    AesBlock128 key_lo,
    AesBlock128 key_hi);

AesBlock128 __fastcall raw_aes192cbc_encrypt(
    AesBlock128 plain,
    AesBlock128 key_lo,
    AesBlock128 key_hi,
    AesBlock128 *iv);
AesBlock128 __fastcall raw_aes192cbc_decrypt(
    AesBlock128 cypher,
    AesBlock128 key_lo,
    AesBlock128 key_hi,
    AesBlock128 *iv);

AesBlock128 __fastcall raw_aes256ecb_encrypt(
    AesBlock128 plain,
    AesBlock128 key_lo,
    AesBlock128 key_hi);
AesBlock128 __fastcall raw_aes256ecb_decrypt(
    AesBlock128 cypher,
    AesBlock128 key_lo,
    AesBlock128 key_hi);

AesBlock128 __fastcall raw_aes256cbc_encrypt(
    AesBlock128 plain,
    AesBlock128 key_lo,
    AesBlock128 key_hi,
    AesBlock128 *iv);
AesBlock128 __fastcall raw_aes256cbc_decrypt(
    AesBlock128 cypher,
    AesBlock128 key_lo,
    AesBlock128 key_hi,
    AesBlock128 *iv);

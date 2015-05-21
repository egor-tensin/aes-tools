/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "data.h"

AesBlock __fastcall aes128ecb_encrypt(
    AesBlock plain,
    AesBlock key);
AesBlock __fastcall aes128ecb_decrypt(
    AesBlock cypher,
    AesBlock key);

AesBlock __fastcall aes192ecb_encrypt(
    AesBlock plain,
    AesBlock key_lo,
    AesBlock key_hi);
AesBlock __fastcall aes192ecb_decrypt(
    AesBlock cypher,
    AesBlock key_lo,
    AesBlock key_hi);

AesBlock __fastcall aes256ecb_encrypt(
    AesBlock plain,
    AesBlock key_lo,
    AesBlock key_hi);
AesBlock __fastcall aes256ecb_decrypt(
    AesBlock cypher,
    AesBlock key_lo,
    AesBlock key_hi);

AesBlock __fastcall aes256cbc_encrypt(
    AesBlock plain,
    AesBlock key_lo,
    AesBlock key_hi,
    AesBlock *iv);
AesBlock __fastcall aes256cbc_decrypt(
    AesBlock cypher,
    AesBlock key_lo,
    AesBlock key_hi,
    AesBlock *iv);

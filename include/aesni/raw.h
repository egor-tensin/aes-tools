/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "data.h"

void __fastcall raw_aes128_expand_key_schedule(
    AesBlock128 key,
    Aes128KeySchedule* key_schedule);
void __fastcall raw_aes128_invert_key_schedule(
    Aes128KeySchedule* key_schedule,
    Aes128KeySchedule* inverted_schedule);

AesBlock128 __fastcall raw_aes128_encrypt_block(
    AesBlock128 plain,
    Aes128KeySchedule* key_schedule);
AesBlock128 __fastcall raw_aes128_decrypt_block(
    AesBlock128 cipher,
    Aes128KeySchedule* inverted_schedule);

void __fastcall raw_aes192_expand_key_schedule(
    AesBlock128 key_lo,
    AesBlock128 key_hi,
    Aes192KeySchedule* key_schedule);
void __fastcall raw_aes192_invert_key_schedule(
    Aes192KeySchedule* key_schedule,
    Aes192KeySchedule* inverted_schedule);

AesBlock128 __fastcall raw_aes192_encrypt_block(
    AesBlock128 plain,
    Aes192KeySchedule* key_schedule);
AesBlock128 __fastcall raw_aes192_decrypt_block(
    AesBlock128 cipher,
    Aes192KeySchedule* inverted_schedule);

void __fastcall raw_aes256_expand_key_schedule(
    AesBlock128 key_lo,
    AesBlock128 key_hi,
    Aes256KeySchedule* key_schedule);
void __fastcall raw_aes256_invert_key_schedule(
    Aes256KeySchedule* key_schedule,
    Aes256KeySchedule* inverted_schedule);

AesBlock128 __fastcall raw_aes256_encrypt_block(
    AesBlock128 plain,
    Aes256KeySchedule* key_schedule);
AesBlock128 __fastcall raw_aes256_decrypt_block(
    AesBlock128 cipher,
    Aes256KeySchedule* inverted_schedule);

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "data.h"

#ifdef __cplusplus
extern "C"
{
#endif

void __fastcall aesni_raw_expand_key_schedule128(
    AesNI_Block128 key,
    AesNI_KeySchedule128* key_schedule);
void __fastcall aesni_raw_invert_key_schedule128(
    AesNI_KeySchedule128* key_schedule,
    AesNI_KeySchedule128* inverted_schedule);

AesNI_Block128 __fastcall aesni_raw_encrypt_block128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule);
AesNI_Block128 __fastcall aesni_raw_decrypt_block128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* inverted_schedule);

void __fastcall aesni_raw_expand_key_schedule192(
    AesNI_Block128 key_lo,
    AesNI_Block128 key_hi,
    AesNI_KeySchedule192* key_schedule);
void __fastcall aesni_raw_invert_key_schedule192(
    AesNI_KeySchedule192* key_schedule,
    AesNI_KeySchedule192* inverted_schedule);

AesNI_Block128 __fastcall aesni_raw_encrypt_block192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule);
AesNI_Block128 __fastcall aesni_raw_decrypt_block192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* inverted_schedule);

void __fastcall aesni_raw_expand_key_schedule256(
    AesNI_Block128 key_lo,
    AesNI_Block128 key_hi,
    AesNI_KeySchedule256* key_schedule);
void __fastcall aesni_raw_invert_key_schedule256(
    AesNI_KeySchedule256* key_schedule,
    AesNI_KeySchedule256* inverted_schedule);

AesNI_Block128 __fastcall aesni_raw_encrypt_block256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule);
AesNI_Block128 __fastcall aesni_raw_decrypt_block256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* inverted_schedule);

#ifdef __cplusplus
}
#endif

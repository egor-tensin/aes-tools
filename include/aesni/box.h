/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "algorithm.h"
#include "data.h"
#include "error.h"
#include "mode.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef union
{
    AesNI_KeySchedule128 aes128_key_schedule;
    AesNI_KeySchedule192 aes192_key_schedule;
    AesNI_KeySchedule256 aes256_key_schedule;
}
AesNI_EncryptionParams;

typedef union
{
    AesNI_KeySchedule128 aes128_key_schedule;
    AesNI_KeySchedule192 aes192_key_schedule;
    AesNI_KeySchedule256 aes256_key_schedule;
}
AesNI_DecryptionParams;

typedef union
{
    AesNI_Block128 aes_block;
}
AesNI_State;

typedef union
{
    AesNI_Block128 aes128_key;
    AesNI_Block192 aes192_key;
    AesNI_Block256 aes256_key;
}
AesNI_AlgorithmParams;

typedef struct
{
    AesNI_Algorithm algorithm;
    AesNI_EncryptionParams encrypt_params;
    AesNI_DecryptionParams decrypt_params;
    AesNI_Mode mode;
    AesNI_State iv;
}
AesNI_Box;

AesNI_StatusCode aesni_box_init(
    AesNI_Box*,
    AesNI_Algorithm,
    const AesNI_AlgorithmParams*,
    AesNI_Mode,
    const AesNI_State* iv,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_box_encrypt(
    AesNI_Box*,
    const AesNI_State*,
    AesNI_State*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_box_decrypt(
    AesNI_Box*,
    const AesNI_State*,
    AesNI_State*,
    AesNI_ErrorDetails*);

#ifdef __cplusplus
}
#endif

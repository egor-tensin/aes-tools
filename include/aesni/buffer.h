/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 *
 * \brief Declares variable-length buffer encryption/decryption functions.
 */

#pragma once

#include "error.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

AesNI_StatusCode aesni_encrypt_buffer_ecb128(
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AesNI_KeySchedule128* key_schedule,
    AesNI_ErrorDetails* err_details);
AesNI_StatusCode aesni_decrypt_buffer_ecb128(
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AesNI_KeySchedule128* inverted_schedule,
    AesNI_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

size_t aesni_encrypt_buffer_ecb128(
    const void* src,
    size_t src_size,
    void* dest,
    AesNI_KeySchedule128* key_schedule);
size_t aesni_decrypt_buffer_ecb128(
    const void* src,
    size_t src_size,
    void* dest,
    AesNI_KeySchedule128* inverted_schedule);

#ifdef __cplusplus
}
#endif

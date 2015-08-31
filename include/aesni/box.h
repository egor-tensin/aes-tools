/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "algorithm.h"
#include "box_data.h"
#include "error.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

AesNI_StatusCode aesni_box_init(
    AesNI_Box* box,
    AesNI_Algorithm algorithm,
    const AesNI_BoxKey* box_key,
    AesNI_Mode mode,
    const AesNI_BoxBlock* iv,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_box_encrypt_block(
    AesNI_Box* box,
    const AesNI_BoxBlock* plaintext,
    AesNI_BoxBlock* ciphertext,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_box_decrypt_block(
    AesNI_Box* box,
    const AesNI_BoxBlock* ciphertext,
    AesNI_BoxBlock* plaintext,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_box_encrypt_buffer(
    AesNI_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_box_decrypt_buffer(
    AesNI_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AesNI_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

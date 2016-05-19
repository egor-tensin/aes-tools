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

AES_StatusCode aes_box_init(
    AES_Box* box,
    AES_Algorithm algorithm,
    const AES_BoxKey* box_key,
    AES_Mode mode,
    const AES_BoxBlock* iv,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_box_parse_key(
    AES_BoxKey* dest,
    AES_Algorithm algorithm,
    const char* src,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_box_parse_block(
    AES_BoxBlock* dest,
    AES_Algorithm algorithm,
    const char* src,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_box_format_key(
    AES_BoxKeyString* dest,
    AES_Algorithm algorithm,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_box_format_block(
    AES_BoxBlockString* dest,
    AES_Algorithm algorithm,
    const AES_BoxBlock* src,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_box_encrypt_block(
    AES_Box* box,
    const AES_BoxBlock* plaintext,
    AES_BoxBlock* ciphertext,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_box_decrypt_block(
    AES_Box* box,
    const AES_BoxBlock* ciphertext,
    AES_BoxBlock* plaintext,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_box_encrypt_buffer(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_box_decrypt_buffer(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AES_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

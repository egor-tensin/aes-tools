/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "box_data.h"
#include "error.h"

#ifdef __cplusplus
extern "C"
{
#endif

AesNI_StatusCode aesni_box_init(
    AesNI_Box* box,
    AesNI_BoxAlgorithm algorithm,
    const AesNI_BoxAlgorithmParams* algorithm_params,
    AesNI_BoxMode mode,
    const AesNI_BoxBlock* iv,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_box_encrypt(
    AesNI_Box* box,
    const AesNI_BoxBlock* plaintext,
    AesNI_BoxBlock* ciphertext,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_box_decrypt(
    AesNI_Box* box,
    const AesNI_BoxBlock* ciphertext,
    AesNI_BoxBlock* plaintext,
    AesNI_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

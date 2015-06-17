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
    AesNI_Box*,
    AesNI_BoxAlgorithm,
    const AesNI_BoxAlgorithmParams*,
    AesNI_BoxMode,
    const AesNI_BoxBlock* iv,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_box_encrypt(
    AesNI_Box*,
    const AesNI_BoxBlock*,
    AesNI_BoxBlock*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_box_decrypt(
    AesNI_Box*,
    const AesNI_BoxBlock*,
    AesNI_BoxBlock*,
    AesNI_ErrorDetails*);

#ifdef __cplusplus
}
#endif

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "error.h"

#include <stdlib.h>

typedef enum
{
    AESNI_PADDING_PKCS7,
}
AesNI_PaddingMethod;

AesNI_StatusCode aesni_extract_padding_size(
    AesNI_PaddingMethod,
    const void* src,
    size_t src_size,
    size_t* padding_size,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_fill_with_padding(
    AesNI_PaddingMethod,
    void* dest,
    size_t padding_size,
    AesNI_ErrorDetails*);

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

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    AES_PADDING_PKCS7,
}
AES_PaddingMethod;

AES_StatusCode aes_extract_padding_size(
    AES_PaddingMethod,
    const void* src,
    size_t src_size,
    size_t* padding_size,
    AES_ErrorDetails*);

AES_StatusCode aes_fill_with_padding(
    AES_PaddingMethod,
    void* dest,
    size_t padding_size,
    AES_ErrorDetails*);

#ifdef __cplusplus
}
#endif

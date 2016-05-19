/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aes/all.h>

#include <stdlib.h>
#include <string.h>

static AES_StatusCode aes_extract_padding_size_pkcs7(
    const void* src,
    size_t src_size,
    size_t* padding_size,
    AES_ErrorDetails* err_details)
{
    const unsigned char* cursor = (const unsigned char*) src + src_size - 1;
    *padding_size = *cursor;

    for (size_t i = 1; i < *padding_size; ++i)
        if (cursor[0 - i] != *padding_size)
            return aes_error_invalid_pkcs7_padding(err_details);

    return AES_SUCCESS;
}

AES_StatusCode aes_extract_padding_size(
    AES_PaddingMethod method,
    const void* src,
    size_t src_size,
    size_t* padding_size,
    AES_ErrorDetails* err_details)
{
    assert(src);
    assert(padding_size);

    if (src == NULL)
        return aes_error_null_argument(err_details, "src");
    if (padding_size == NULL)
        return aes_error_null_argument(err_details, "padding_size");

    switch (method)
    {
        case AES_PADDING_PKCS7:
            return aes_extract_padding_size_pkcs7(
                src, src_size, padding_size, err_details);

        default:
            return aes_error_not_implemented(
                err_details, "unsupported padding method");
    }
}

static AES_StatusCode aes_fill_with_padding_pkcs7(
    void* dest,
    size_t padding_size,
    AES_ErrorDetails* err_details)
{
    memset(dest, padding_size, padding_size);
    return AES_SUCCESS;
}

AES_StatusCode aes_fill_with_padding(
    AES_PaddingMethod method,
    void* dest,
    size_t padding_size,
    AES_ErrorDetails* err_details)
{
    assert(dest);

    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    switch (method)
    {
        case AES_PADDING_PKCS7:
            return aes_fill_with_padding_pkcs7(
                dest, padding_size, err_details);

        default:
            return aes_error_not_implemented(
                err_details, "unsupported padding method");
    }
}

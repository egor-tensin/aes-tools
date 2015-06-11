/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    AESNI_ERROR_SUCCESS,

    AESNI_ERROR_NULL_ARGUMENT,

    AESNI_ERROR_INVALID_PKCS7_PADDING,
}
AesNI_ErrorCode;

const char* aesni_strerror(AesNI_ErrorCode);

typedef struct
{
    AesNI_ErrorCode ec;

    union
    {
        struct
        {
            char arg_name[32];
        }
        null_arg;
    }
    params;
}
AesNI_ErrorDetails;

void aesni_make_error_success(AesNI_ErrorDetails*);
void aesni_make_error_null_argument(AesNI_ErrorDetails*, const char* arg_name);
void aesni_make_error_invalid_pkcs7_padding(AesNI_ErrorDetails*);

#ifdef __cplusplus
}
#endif

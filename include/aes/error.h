// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    AES_SUCCESS,
    AES_NULL_ARGUMENT_ERROR,
    AES_PARSE_ERROR,
    AES_INVALID_PKCS7_PADDING_ERROR,
    AES_NOT_IMPLEMENTED_ERROR,
    AES_MISSING_PADDING_ERROR,
    AES_MEMORY_ALLOCATION_ERROR,
}
AES_StatusCode;

static __inline int aes_is_error(AES_StatusCode ec)
{
    return ec != AES_SUCCESS;
}

const char* aes_strerror(AES_StatusCode ec);

#define AES_MAX_CALL_STACK_LENGTH 32

typedef struct
{
    AES_StatusCode ec; ///< Error code

    union
    {
        struct { char param_name[32]; } null_arg;
        struct
        {
            char src[128];
            char what[32];
        }
        parse_error;
        struct { char what[128]; } not_implemented;
    }
    params;

    void* call_stack[AES_MAX_CALL_STACK_LENGTH];
    size_t call_stack_len;
}
AES_ErrorDetails;

static __inline AES_StatusCode aes_get_error_code(
    const AES_ErrorDetails* err_details)
{
    return err_details->ec;
}

size_t aes_format_error(
    const AES_ErrorDetails* err_details,
    char* dest,
    size_t dest_size);

AES_StatusCode aes_success(
    AES_ErrorDetails* err_details);

AES_StatusCode aes_error_null_argument(
    AES_ErrorDetails* err_details,
    const char* param_name);

AES_StatusCode aes_error_parse(
    AES_ErrorDetails* err_details,
    const char* src,
    const char* what);

AES_StatusCode aes_error_invalid_pkcs7_padding(
    AES_ErrorDetails* err_details);

AES_StatusCode aes_error_not_implemented(
    AES_ErrorDetails* err_details,
    const char* what);

AES_StatusCode aes_error_missing_padding(
    AES_ErrorDetails* err_details);

AES_StatusCode aes_error_memory_allocation(
    AES_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

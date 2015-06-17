/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* err_msgs[] =
{
    "OK",
    "Invalid argument value NULL",
    "Couldn't parse",
    "Invalid PKCS7 padding (wrong key?)",
    "Not implemented",
};

const char* aesni_strerror(AesNI_StatusCode ec)
{
    return err_msgs[ec];
}

static size_t aesni_format_error_strerror(
    const AesNI_ErrorDetails* err_details,\
    char* dest,
    size_t dest_size)
{
    const AesNI_StatusCode ec = aesni_get_error_code(err_details);
    const char* const msg = aesni_strerror(ec);

    if (dest == NULL && dest_size == 0)
        return strlen(msg) + 1;

    strncpy(dest, msg, dest_size);
    dest[dest_size - 1] = '\0';
    return strlen(dest);
}

static size_t aesni_format_null_argument_error(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size)
{
    static const char* const fmt = "Invalid argument value NULL (argument name: '%s')";
    const char* const param_name = err_details->params.null_arg_error.param_name;

    if (dest == NULL && dest_size == 0)
        return _snprintf(NULL, 0, fmt, param_name) + 1;

    _snprintf(dest, dest_size, fmt, param_name);
    return strlen(dest);
}

static size_t aesni_format_parse_error(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size)
{
    static const char* const fmt = "Couldn't parse '%s'";
    const char* const src = err_details->params.parse_error.src;

    if (dest == NULL)
        return _snprintf(NULL, 0, fmt, src) + 1;

    _snprintf(dest, dest_size, fmt, src);
    return strlen(dest);
}

typedef size_t (*AesNI_ErrorFormatter)(const AesNI_ErrorDetails*, char*, size_t);

static AesNI_ErrorFormatter err_formatters[] =
{
    &aesni_format_error_strerror,
    &aesni_format_null_argument_error,
    &aesni_format_error_strerror,
    &aesni_format_error_strerror,
    &aesni_format_error_strerror,
};

size_t aesni_format_error(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size)
{
    assert(err_details);

    return err_formatters[err_details->ec](err_details, dest, dest_size);
}

static AesNI_StatusCode aesni_make_error(
    AesNI_ErrorDetails* err_details,
    AesNI_StatusCode ec)
{
    if (err_details == NULL)
        return ec;

    return err_details->ec = ec;
}

AesNI_StatusCode aesni_initialize_error_details(
    AesNI_ErrorDetails* err_details)
{
    return aesni_make_error(err_details, AESNI_SUCCESS);
}

AesNI_StatusCode aesni_make_null_argument_error(
    AesNI_ErrorDetails* err_details,
    const char* param_name)
{
    AesNI_StatusCode status = aesni_make_error(
        err_details, AESNI_NULL_ARGUMENT_ERROR);

    const size_t param_name_size = sizeof(err_details->params.null_arg_error.param_name);
    strncpy(err_details->params.null_arg_error.param_name, param_name, param_name_size);
    err_details->params.null_arg_error.param_name[param_name_size - 1] = '\0';

    return status;
}

AesNI_StatusCode aesni_make_parse_error(
    AesNI_ErrorDetails* err_details,
    const char* src)
{
    AesNI_StatusCode status = aesni_make_error(err_details, AESNI_PARSE_ERROR);

    const size_t src_size = sizeof(err_details->params.parse_error.src);
    strncpy(err_details->params.parse_error.src, src, src_size);
    err_details->params.parse_error.src[src_size - 1] = '\0';

    return status;
}

AesNI_StatusCode aesni_make_invalid_pkcs7_padding_error(
    AesNI_ErrorDetails* err_details)
{
    return aesni_make_error(err_details, AESNI_INVALID_PKCS7_PADDING_ERROR);
}

AesNI_StatusCode aesni_error_not_implemented(
    AesNI_ErrorDetails* err_details)
{
    return aesni_make_error(err_details, AESNI_NOT_IMPLEMENTED);
}

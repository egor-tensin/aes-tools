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
    "Success",
    "Invalid argument value NULL",
    "Invalid PKCS7 padding (wrong key?)",
};

const char* aesni_strerror(AesNI_ErrorCode ec)
{
    return err_msgs[ec];
}

static size_t aesni_format_error_simple(
    const AesNI_ErrorDetails* err_details,\
    char* dest,
    size_t dest_size)
{
    const AesNI_ErrorCode ec = aesni_get_error_code(err_details);
    const char* const msg = aesni_strerror(ec);

    if (dest == NULL && dest_size == 0)
        return strlen(msg) + 1;

    strncpy(dest, msg, dest_size);
    dest[dest_size - 1] = '\0';
    return strlen(dest);
}

static size_t aesni_format_error_null_argument(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size)
{
    static const char* const fmt = "Invalid argument value NULL (argument name: '%s')";
    const char* const arg_name = err_details->params.null_arg.arg_name;

    if (dest == NULL && dest_size == 0)
        return _snprintf(NULL, 0, fmt, arg_name) + 1;

    _snprintf(dest, dest_size, fmt, arg_name);
    return strlen(dest);
}

typedef size_t (*AesNI_ErrorFormatter)(const AesNI_ErrorDetails*, char*, size_t);

static AesNI_ErrorFormatter err_formatters[] =
{
    &aesni_format_error_simple,
    &aesni_format_error_null_argument,
    &aesni_format_error_simple,
};

size_t aesni_format_error(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size)
{
    assert(err_details);

    return err_formatters[err_details->ec](err_details, dest, dest_size);
}

static void aesni_make_error(
    AesNI_ErrorDetails* err_details,
    AesNI_ErrorCode ec)
{
    if (err_details == NULL)
        return;

    err_details->ec = ec;
}

void aesni_make_error_success(
    AesNI_ErrorDetails* err_details)
{
    if (err_details == NULL)
        return;

    aesni_make_error(err_details, AESNI_ERROR_SUCCESS);
}

void aesni_make_error_null_argument(
    AesNI_ErrorDetails* err_details,
    const char* arg_name)
{
    if (err_details == NULL)
        return;

    aesni_make_error(err_details, AESNI_ERROR_NULL_ARGUMENT);

    const size_t arg_name_size = sizeof(err_details->params.null_arg.arg_name);
    strncpy(err_details->params.null_arg.arg_name, arg_name, arg_name_size);
    err_details->params.null_arg.arg_name[arg_name_size - 1] = '\0';
}

void aesni_make_error_invalid_pkcs7_padding(
    AesNI_ErrorDetails* err_details)
{
    if (err_details == NULL)
        return;

    aesni_make_error(err_details, AESNI_ERROR_INVALID_PKCS7_PADDING);
}

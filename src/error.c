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

static void aesni_fill_string(char* dest, size_t dest_size, const char* src)
{
    strncpy(dest, src, dest_size);
    dest[dest_size - 1] = '\0';
}

static const char* aesni_strerror_messages[] =
{
    "Success",
    "Invalid argument value NULL",
    "Couldn't parse",
    "Invalid PKCS7 padding (wrong key?)",
    "Not implemented",
};

const char* aesni_strerror(AesNI_StatusCode ec)
{
    return aesni_strerror_messages[ec];
}

static size_t aesni_format_error_strerror(
    const AesNI_ErrorDetails* err_details,\
    char* dest,
    size_t dest_size)
{
    const AesNI_StatusCode ec = aesni_get_error_code(err_details);
    const char* const msg = aesni_strerror(ec);

    if (dest == NULL)
        return strlen(msg) + 1;

    aesni_fill_string(dest, dest_size, msg);
    return strlen(dest);
}

static size_t aesni_format_null_argument_error(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size)
{
    static const char* const fmt = "Invalid argument value NULL (argument name: '%s')";
    const char* const param_name = err_details->params.null_arg.param_name;

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
    static const char* const fmt = "Couldn't parse '%s' (possibly not complete input) as %s";
    const char* const src = err_details->params.parse_error.src;
    const char* const what = err_details->params.parse_error.what;

    if (dest == NULL)
        return _snprintf(NULL, 0, fmt, src, what) + 1;

    _snprintf(dest, dest_size, fmt, src, what);
    return strlen(dest);
}

static size_t aesni_format_not_implemented_error(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size)
{
    static const char* const fmt = "Not implemented: %s";
    const char* const src = err_details->params.not_implemented.what;

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
    &aesni_format_parse_error,
    &aesni_format_error_strerror,
    &aesni_format_not_implemented_error,
};

size_t aesni_format_error(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size)
{
    assert(err_details);

    return err_formatters[err_details->ec](err_details, dest, dest_size);
}

#ifdef WIN32
#include <Windows.h>

static void aesni_collect_call_stack(AesNI_ErrorDetails* err_details)
{
    err_details->call_stack_size = CaptureStackBackTrace(1, AESNI_MAX_CALL_STACK_LENGTH, err_details->call_stack, NULL);
}
#else
static void aesni_collect_call_stack(AesNI_ErrorDetails* err_details)
{
    err_details->call_stack_size = 0;
}
#endif

static AesNI_StatusCode aesni_make_error(
    AesNI_ErrorDetails* err_details,
    AesNI_StatusCode ec)
{
    if (err_details == NULL)
        return ec;

    if (aesni_is_error(ec))
        aesni_collect_call_stack(err_details);

    return err_details->ec = ec;
}

AesNI_StatusCode aesni_success(
    AesNI_ErrorDetails* err_details)
{
    return aesni_make_error(err_details, AESNI_SUCCESS);
}

AesNI_StatusCode aesni_error_null_argument(
    AesNI_ErrorDetails* err_details,
    const char* param_name)
{
    AesNI_StatusCode status = aesni_make_error(err_details, AESNI_NULL_ARGUMENT_ERROR);

    if (err_details != NULL)
        aesni_fill_string(
            err_details->params.null_arg.param_name,
            sizeof(err_details->params.null_arg.param_name), param_name);

    return status;
}

AesNI_StatusCode aesni_error_parse(
    AesNI_ErrorDetails* err_details,
    const char* src,
    const char* what)
{
    AesNI_StatusCode status = aesni_make_error(err_details, AESNI_PARSE_ERROR);

    if (err_details != NULL)
    {
        aesni_fill_string(
            err_details->params.parse_error.src,
            sizeof(err_details->params.parse_error.src), src);
        aesni_fill_string(
            err_details->params.parse_error.what,
            sizeof(err_details->params.parse_error.what), what);
    }

    return status;
}

AesNI_StatusCode aesni_error_invalid_pkcs7_padding(
    AesNI_ErrorDetails* err_details)
{
    return aesni_make_error(err_details, AESNI_INVALID_PKCS7_PADDING_ERROR);
}

AesNI_StatusCode aesni_error_not_implemented(
    AesNI_ErrorDetails* err_details,
    const char* what)
{
    AesNI_StatusCode status = aesni_make_error(err_details, AESNI_NOT_IMPLEMENTED_ERROR);

    if (err_details != NULL)
        aesni_fill_string(
            err_details->params.not_implemented.what,
            sizeof(err_details->params.not_implemented.what), what);

    return status;
}

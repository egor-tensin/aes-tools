/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

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

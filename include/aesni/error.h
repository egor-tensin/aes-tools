/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 *
 * \brief Declares error codes, error formatting functions, etc.
 */

#pragma once

/**
 * \defgroup aesni_error_handling Error handling
 * \ingroup aesni
 * \brief Error data structures and formatting functions.
 *
 * Some library functions cannot fail, which is simple.
 * Other functions return an error code.
 * You can check if a function exited with an error by passing the returned
 * error code to aesni_is_error().
 *
 * Some possibly-may-fail functions accept a pointer to an "error details"
 * structure.
 * This pointer can always be `NULL`.
 * In this case, simply an error code is returned.
 * Otherwise, the error details structure is filled with appropriate info about
 * the error, possibly including a few details like invalid arguments names,
 * etc.
 *
 * You can format an error details structure using the formatting functions.
 * \{
 */

#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * \brief API status codes.
 */
typedef enum
{
    AESNI_SUCCESS,             ///< Everything went fine
    AESNI_NULL_ARGUMENT_ERROR, ///< Invalid argument value NULL
    AESNI_PARSE_ERROR,         ///< Couldn't parse
    AESNI_INVALID_PKCS7_PADDING_ERROR, ///< Invalid PKCS7 padding
}
AesNI_StatusCode;

static __inline int aesni_is_error(AesNI_StatusCode ec)
{
    return ec != AESNI_SUCCESS;
}

/**
 * \brief Retrieves a simple error message for an error code.
 *
 * For example,
 * \code{.c}
 * printf("%s\n", aesni_strerror(AESNI_NULL_ARGUMENT_ERROR));
 * \endcode
 * would print
 * \code
 * Invalid argument value NULL
 * \endcode
 *
 * \param[in] ec The error code.
 * \return A pointer to a statically-allocated C string.
 */
const char* aesni_strerror(AesNI_StatusCode ec);

/**
 * \brief Stores error details: error code & possibly a few parameters.
 */
typedef struct
{
    AesNI_StatusCode ec; ///< Error code

    union
    {
        struct
        {
            char param_name[32]; ///< Name of the NULL argument
        }
        null_arg_error;
        ///< `NULL` argument error (AESNI_NULL_ARGUMENT_ERROR) parameters

        struct
        {
            char src[128]; ///< The string that failed to be parsed
        }
        parse_error;
        ///< Parse error (AESNI_PARSE_ERROR) parameters
    }
    params;
}
AesNI_ErrorDetails;

/**
 * \brief Extracts an error code from error details.
 *
 * \param[in] err_details The error details structure. Must not be `NULL`.
 * \return The error code stored in the error details.
 */
static __inline AesNI_StatusCode aesni_get_error_code(
    const AesNI_ErrorDetails* err_details)
{
    return err_details->ec;
}

/**
 * \brief Formats a pretty error message, including error parameters.
 *
 * \param[in] err_details The pointer to error details. Must not be `NULL`.
 * \param[out] dest The pointer to the destination string buffer.
 * \param[in] dest_size The size of the destination buffer, in bytes.
 * \return If `dest` is NULL, the number of bytes required to store the full
 * error message, and the number of characters written (excluding the
 * terminating '\0' character) otherwise.
 */
size_t aesni_format_error(
    const AesNI_ErrorDetails* err_details,
    char* dest,
    size_t dest_size);

/**
 * \brief Initializes an error details structure.
 *
 * \param[out] err_details The error details structure to fill.
 */
AesNI_StatusCode aesni_initialize_error_details(
    AesNI_ErrorDetails* err_details);

/**
 * \brief Builds error details from a `NULL` argument error.
 *
 * \param[out] err_details The error details structure to fill.
 * \param[in] param_name The parameter name. Must not be `NULL`.
 */
AesNI_StatusCode aesni_make_null_argument_error(
    AesNI_ErrorDetails* err_details,
    const char* param_name);

/**
 * \brief Builds error details from a parse error.
 *
 * \param[out] err_details The error details structure to fill.
 * \param[in] src The string that failed to be parsed.
 */
AesNI_StatusCode aesni_make_parse_error(
    AesNI_ErrorDetails* err_details,
    const char* src);

/**
 * \brief Builds error details from an invalid PKCS7 padding error.
 *
 * \param[out] err_details The error details structure to fill.
 */
AesNI_StatusCode aesni_make_invalid_pkcs7_padding_error(
    AesNI_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

/**
 * \}
 */

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

/**
 * \defgroup aes_error_handling Error handling
 * \ingroup aes
 * \brief Error data structures and formatting functions.
 *
 * Some library functions cannot fail, which is simple.
 * Other functions return an error code.
 * You can check if a function exited with an error by passing the returned
 * error code to aes_is_error().
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
    AES_SUCCESS,                     ///< Everything went fine
    AES_NULL_ARGUMENT_ERROR,         ///< Invalid argument value NULL
    AES_PARSE_ERROR,                 ///< Couldn't parse
    AES_INVALID_PKCS7_PADDING_ERROR, ///< Invalid PKCS7 padding while decrypting
    AES_NOT_IMPLEMENTED_ERROR,       ///< Not implemented
    AES_MISSING_PADDING_ERROR,
    AES_MEMORY_ALLOCATION_ERROR,
}
AES_StatusCode;

static __inline int aes_is_error(AES_StatusCode ec)
{
    return ec != AES_SUCCESS;
}

/**
 * \brief Retrieves a simple error message for an error code.
 *
 * For example,
 * \code{.c}
 * printf("%s\n", aes_strerror(AES_NULL_ARGUMENT_ERROR));
 * \endcode
 * would print
 * \code
 * Invalid argument value NULL
 * \endcode
 *
 * \param[in] ec The error code.
 * \return A pointer to a statically-allocated C string.
 */
const char* aes_strerror(AES_StatusCode ec);

#define AES_MAX_CALL_STACK_LENGTH 32

/**
 * \brief Stores error details: error code & possibly a few parameters.
 */
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
    size_t call_stack_size;
}
AES_ErrorDetails;

/**
 * \brief Extracts an error code from error details.
 *
 * \param[in] err_details The error details structure. Must not be `NULL`.
 * \return The error code stored in the error details.
 */
static __inline AES_StatusCode aes_get_error_code(
    const AES_ErrorDetails* err_details)
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
size_t aes_format_error(
    const AES_ErrorDetails* err_details,
    char* dest,
    size_t dest_size);

/**
 * \brief Initializes an error details structure.
 *
 * \param[out] err_details The error details structure to fill.
 */
AES_StatusCode aes_success(
    AES_ErrorDetails* err_details);

/**
 * \brief Builds error details from a `NULL` argument error.
 *
 * \param[out] err_details The error details structure to fill.
 * \param[in] param_name The parameter name. Must not be `NULL`.
 */
AES_StatusCode aes_error_null_argument(
    AES_ErrorDetails* err_details,
    const char* param_name);

/**
 * \brief Builds error details from a parse error.
 *
 * \param[out] err_details The error details structure to fill.
 * \param[in] src The string that failed to be parsed.
 */
AES_StatusCode aes_error_parse(
    AES_ErrorDetails* err_details,
    const char* src,
    const char* what);

/**
 * \brief Builds error details from an invalid PKCS7 padding error.
 *
 * \param[out] err_details The error details structure to fill.
 */
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

/**
 * \}
 */

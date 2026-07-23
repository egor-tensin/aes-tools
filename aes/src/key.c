/*
 * Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

AES_StatusCode aes128_format_key(
    AES128_KeyString* str,
    const AES128_Key* key,
    AES_ErrorDetails* err_details
) {
    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (key == NULL)
        return aes_error_null_argument(err_details, "key");

    char* cursor = aes_format_block_hex(str->str, key->key);
    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes192_format_key(
    AES192_KeyString* str,
    const AES192_Key* key,
    AES_ErrorDetails* err_details
) {
    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (key == NULL)
        return aes_error_null_argument(err_details, "key");

    char* cursor = aes_format_block_hex(str->str, key->lo);
    cursor = aes_format_block_hex_partial(cursor, key->hi, 8);
    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes256_format_key(
    AES256_KeyString* str,
    const AES256_Key* key,
    AES_ErrorDetails* err_details
) {
    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (key == NULL)
        return aes_error_null_argument(err_details, "key");

    char* cursor = aes_format_block_hex(str->str, key->lo);
    cursor = aes_format_block_hex(cursor, key->hi);
    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes128_parse_key(AES128_Key* dest, const char* src, AES_ErrorDetails* err_details) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_parse_block(&dest->key, src, err_details);
}

AES_StatusCode aes192_parse_key(AES192_Key* dest, const char* src, AES_ErrorDetails* err_details) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    AES_ALIGN(unsigned char, 16) bytes[32];
    memset(bytes, 0x00, sizeof(bytes));

    AES_StatusCode status = aes_parse_hex_string(bytes, src, 24, err_details);
    if (aes_is_error(status))
        return status;

    dest->lo = aes_load_block_aligned(bytes);
    dest->hi = aes_load_block_aligned(bytes + 16);

    return status;
}

AES_StatusCode aes256_parse_key(AES256_Key* dest, const char* src, AES_ErrorDetails* err_details) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    AES_ALIGN(unsigned char, 16) bytes[32];

    AES_StatusCode status = aes_parse_hex_string(bytes, src, sizeof(bytes), err_details);
    if (aes_is_error(status))
        return status;

    dest->lo = aes_load_block_aligned(bytes);
    dest->hi = aes_load_block_aligned(bytes + 16);

    return status;
}

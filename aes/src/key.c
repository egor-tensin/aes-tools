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

    char* cursor = str->str;

    AES_ALIGN(unsigned char, 16) bytes[16];
    aes_store_block_aligned(bytes, key->key);

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", bytes[i]);

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

    char* cursor = str->str;

    {
        AES_ALIGN(unsigned char, 16) bytes[16];
        aes_store_block_aligned(bytes, key->lo);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    {
        AES_ALIGN(unsigned char, 16) bytes[16];
        aes_store_block_aligned(bytes, key->hi);

        for (int i = 0; i < 8; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

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

    char* cursor = str->str;

    {
        AES_ALIGN(unsigned char, 16) bytes[16];
        aes_store_block_aligned(bytes, key->lo);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    {
        AES_ALIGN(unsigned char, 16) bytes[16];
        aes_store_block_aligned(bytes, key->hi);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes128_parse_key(AES128_Key* dest, const char* src, AES_ErrorDetails* err_details) {
    return aes_parse_block(&dest->key, src, err_details);
}

AES_StatusCode aes192_parse_key(AES192_Key* dest, const char* src, AES_ErrorDetails* err_details) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    const char* cursor = src;

    {
        AES_ALIGN(unsigned char, 16) bytes[16];

        for (int i = 0; i < 16; ++i) {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aes_error_parse(err_details, src, "a 192-bit block");
            bytes[i] = (unsigned char)byte;
            cursor += n;
        }

        dest->lo = aes_load_block_aligned(bytes);
    }

    {
        AES_ALIGN(unsigned char, 16) bytes[16];

        for (int i = 0; i < 8; ++i) {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aes_error_parse(err_details, src, "a 192-bit block");
            bytes[i] = (unsigned char)byte;
            cursor += n;
        }

        memset(bytes + 8, 0x00, 8);
        dest->hi = aes_load_block_aligned(bytes);
    }

    return AES_SUCCESS;
}

AES_StatusCode aes256_parse_key(AES256_Key* dest, const char* src, AES_ErrorDetails* err_details) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    const char* cursor = src;

    {
        AES_ALIGN(unsigned char, 16) bytes[16];

        for (int i = 0; i < 16; ++i) {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aes_error_parse(err_details, src, "a 256-bit block");
            bytes[i] = (unsigned char)byte;
            cursor += n;
        }

        dest->lo = aes_load_block_aligned(bytes);
    }

    {
        AES_ALIGN(unsigned char, 16) bytes[16];

        for (int i = 0; i < 16; ++i) {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aes_error_parse(err_details, src, "a 256-bit block");
            bytes[i] = (unsigned char)byte;
            cursor += n;
        }

        dest->hi = aes_load_block_aligned(bytes);
    }

    return AES_SUCCESS;
}

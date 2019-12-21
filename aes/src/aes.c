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

AES_StatusCode aes_AES_format_block(
    AES_AES_BlockString* str,
    const AES_AES_Block* block,
    AES_ErrorDetails* err_details)
{
    assert(str);
    assert(block);

    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (block == NULL)
        return aes_error_null_argument(err_details, "block");

    char* cursor = str->str;

    AES_ALIGN(unsigned char, 16) bytes[16];
    aes_store_block128_aligned(bytes, *block);

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", bytes[i]);

    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes_AES_format_block_as_matrix(
    AES_AES_BlockMatrixString* str,
    const AES_AES_Block* block,
    AES_ErrorDetails* err_details)
{
    assert(str);
    assert(block);

    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (block == NULL)
        return aes_error_null_argument(err_details, "block");

    char* cursor = str->str;

    AES_ALIGN(unsigned char, 16) bytes[4][4];
    aes_store_block128_aligned(bytes, *block);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 3; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[3][i]);
    }

    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes_AES_print_block(
    const AES_AES_Block* block,
    AES_ErrorDetails* err_details)
{
    assert(block);

    if (block == NULL)
        return aes_error_null_argument(err_details, "block");

    AES_StatusCode ec = AES_SUCCESS;
    AES_AES_BlockString str;

    if (aes_is_error(ec = aes_AES_format_block(&str, block, err_details)))
        return ec;

    printf("%s\n", str.str);
    return ec;
}

AES_StatusCode aes_AES_print_block_as_matrix(
    const AES_AES_Block* block,
    AES_ErrorDetails* err_details)
{
    assert(block);

    if (block == NULL)
        return aes_error_null_argument(err_details, "block");

    AES_StatusCode ec = AES_SUCCESS;
    AES_AES_BlockMatrixString str;

    if (aes_is_error(ec = aes_AES_format_block_as_matrix(&str, block, err_details)))
        return ec;

    printf("%s", str.str);
    return ec;
}

AES_StatusCode aes_AES_parse_block(
    AES_AES_Block* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    const char* cursor = src;

    AES_ALIGN(unsigned char, 16) bytes[16];

    for (int i = 0; i < 16; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
            return aes_error_parse(err_details, src, "a 128-bit block");
        bytes[i] = (unsigned char) byte;
        cursor += n;
    }

    *dest = aes_load_block128_aligned(bytes);
    return AES_SUCCESS;
}

AES_StatusCode aes_AES128_format_key(
    AES_AES128_KeyString* str,
    const AES_AES128_Key* key,
    AES_ErrorDetails* err_details)
{
    assert(str);
    assert(key);

    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (key == NULL)
        return aes_error_null_argument(err_details, "key");

    char* cursor = str->str;

    AES_ALIGN(unsigned char, 16) bytes[16];
    aes_store_block128_aligned(bytes, key->key);

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", bytes[i]);

    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes_AES192_format_key(
    AES_AES192_KeyString* str,
    const AES_AES192_Key* key,
    AES_ErrorDetails* err_details)
{
    assert(str);
    assert(key);

    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (key == NULL)
        return aes_error_null_argument(err_details, "key");

    char* cursor = str->str;

    {
        AES_ALIGN(unsigned char, 16) bytes[16];
        aes_store_block128_aligned(bytes, key->lo);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    {
        AES_ALIGN(unsigned char, 16) bytes[16];
        aes_store_block128_aligned(bytes, key->hi);

        for (int i = 0; i < 8; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes_AES256_format_key(
    AES_AES256_KeyString* str,
    const AES_AES256_Key* key,
    AES_ErrorDetails* err_details)
{
    assert(str);
    assert(key);

    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (key == NULL)
        return aes_error_null_argument(err_details, "key");

    char* cursor = str->str;

    {
        AES_ALIGN(unsigned char, 16) bytes[16];
        aes_store_block128_aligned(bytes, key->lo);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    {
        AES_ALIGN(unsigned char, 16) bytes[16];
        aes_store_block128_aligned(bytes, key->hi);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes_AES128_print_key(
    const AES_AES128_Key* key,
    AES_ErrorDetails* err_details)
{
    return aes_AES_print_block(&key->key, err_details);
}

AES_StatusCode aes_AES192_print_key(
    const AES_AES192_Key* key,
    AES_ErrorDetails* err_details)
{
    assert(key);

    if (key == NULL)
        return aes_error_null_argument(err_details, "key");

    AES_StatusCode ec = AES_SUCCESS;
    AES_AES192_KeyString str;

    if (aes_is_error(ec = aes_AES192_format_key(&str, key, err_details)))
        return ec;

    printf("%s\n", str.str);
    return ec;
}

AES_StatusCode aes_AES256_print_key(
    const AES_AES256_Key* key,
    AES_ErrorDetails* err_details)
{
    assert(key);

    if (key == NULL)
        return aes_error_null_argument(err_details, "key");

    AES_StatusCode ec = AES_SUCCESS;
    AES_AES256_KeyString str;

    if (aes_is_error(ec = aes_AES256_format_key(&str, key, err_details)))
        return ec;

    printf("%s\n", str.str);
    return ec;
}

AES_StatusCode aes_AES128_parse_key(
    AES_AES128_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_parse_block(&dest->key, src, err_details);
}

AES_StatusCode aes_AES192_parse_key(
    AES_AES192_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    const char* cursor = src;

    {
        AES_ALIGN(unsigned char, 16) bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aes_error_parse(err_details, src, "a 192-bit block");
            bytes[i] = (unsigned char) byte;
            cursor += n;
        }

        dest->lo = aes_load_block128_aligned(bytes);
    }

    {
        AES_ALIGN(unsigned char, 16) bytes[16];

        for (int i = 0; i < 8; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aes_error_parse(err_details, src, "a 192-bit block");
            bytes[i] = (unsigned char) byte;
            cursor += n;
        }

        memset(bytes + 8, 0x00, 8);
        dest->hi = aes_load_block128_aligned(bytes);
    }

    return AES_SUCCESS;
}

AES_StatusCode aes_AES256_parse_key(
    AES_AES256_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    const char* cursor = src;

    {
        AES_ALIGN(unsigned char, 16) bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aes_error_parse(err_details, src, "a 256-bit block");
            bytes[i] = (unsigned char) byte;
            cursor += n;
        }

        dest->lo = aes_load_block128_aligned(bytes);
    }

    {
        AES_ALIGN(unsigned char, 16) bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aes_error_parse(err_details, src, "a 256-bit block");
            bytes[i] = (unsigned char) byte;
            cursor += n;
        }

        dest->hi = aes_load_block128_aligned(bytes);
    }

    return AES_SUCCESS;
}

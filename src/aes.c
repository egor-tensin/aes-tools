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
#include <string.h>

AesNI_StatusCode aesni_aes_format_block(
    AesNI_Aes_BlockString* str,
    const AesNI_Aes_Block* block,
    AesNI_ErrorDetails* err_details)
{
    assert(str);
    assert(block);

    if (str == NULL)
        return aesni_error_null_argument(err_details, "str");
    if (block == NULL)
        return aesni_error_null_argument(err_details, "block");

    char* cursor = str->str;

    __declspec(align(16)) unsigned char bytes[16];
    aesni_store_block128_aligned(bytes, *block);

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", bytes[i]);

    *cursor = '\0';
    return AESNI_SUCCESS;
}

AesNI_StatusCode aesni_aes_format_block_as_matrix(
    AesNI_Aes_BlockMatrixString* str,
    const AesNI_Aes_Block* block,
    AesNI_ErrorDetails* err_details)
{
    assert(str);
    assert(block);

    if (str == NULL)
        return aesni_error_null_argument(err_details, "str");
    if (block == NULL)
        return aesni_error_null_argument(err_details, "block");

    char* cursor = str->str;

    __declspec(align(16)) unsigned char bytes[4][4];
    aesni_store_block128_aligned(bytes, *block);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 3; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[3][i]);
    }

    *cursor = '\0';
    return AESNI_SUCCESS;
}

AesNI_StatusCode aesni_aes_print_block(
    const AesNI_Aes_Block* block,
    AesNI_ErrorDetails* err_details)
{
    assert(block);

    if (block == NULL)
        return aesni_error_null_argument(err_details, "block");

    AesNI_StatusCode ec = AESNI_SUCCESS;
    AesNI_Aes_BlockString str;

    if (aesni_is_error(ec = aesni_aes_format_block(&str, block, err_details)))
        return ec;

    printf("%s\n", str.str);
    return ec;
}

AesNI_StatusCode aesni_aes_print_block_as_matrix(
    const AesNI_Aes_Block* block,
    AesNI_ErrorDetails* err_details)
{
    assert(block);

    if (block == NULL)
        return aesni_error_null_argument(err_details, "block");

    AesNI_StatusCode ec = AESNI_SUCCESS;
    AesNI_Aes_BlockMatrixString str;

    if (aesni_is_error(ec = aesni_aes_format_block_as_matrix(&str, block, err_details)))
        return ec;

    printf("%s", str.str);
    return ec;
}

AesNI_StatusCode aesni_aes_parse_block(
    AesNI_Aes_Block* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aesni_error_null_argument(err_details, "src");

    const char* cursor = src;

    __declspec(align(16)) unsigned char bytes[16];

    for (int i = 0; i < 16; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
            return aesni_error_parse(err_details, src, "a 128-bit block");
        bytes[i] = (unsigned char) byte;
        cursor += n;
    }

    *dest = aesni_load_block128_aligned(bytes);
    return AESNI_SUCCESS;
}

AesNI_StatusCode aesni_aes128_format_key(
    AesNI_Aes128_KeyString* str,
    const AesNI_Aes128_Key* key,
    AesNI_ErrorDetails* err_details)
{
    return aesni_aes_format_block(str, &key->key, err_details);
}

AesNI_StatusCode aesni_aes192_format_key(
    AesNI_Aes192_KeyString* str,
    const AesNI_Aes192_Key* key,
    AesNI_ErrorDetails* err_details)
{
    assert(str);
    assert(key);

    if (str == NULL)
        return aesni_error_null_argument(err_details, "str");
    if (key == NULL)
        return aesni_error_null_argument(err_details, "key");

    char* cursor = str->str;

    {
        __declspec(align(16)) unsigned char bytes[16];
        aesni_store_block128_aligned(bytes, key->lo);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    {
        __declspec(align(16)) unsigned char bytes[16];
        aesni_store_block128_aligned(bytes, key->hi);

        for (int i = 0; i < 8; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    *cursor = '\0';
    return AESNI_SUCCESS;
}

AesNI_StatusCode aesni_aes256_format_key(
    AesNI_Aes256_KeyString* str,
    const AesNI_Aes256_Key* key,
    AesNI_ErrorDetails* err_details)
{
    assert(str);
    assert(key);

    if (str == NULL)
        return aesni_error_null_argument(err_details, "str");
    if (key == NULL)
        return aesni_error_null_argument(err_details, "key");

    char* cursor = str->str;

    {
        __declspec(align(16)) unsigned char bytes[16];
        aesni_store_block128_aligned(bytes, key->lo);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    {
        __declspec(align(16)) unsigned char bytes[16];
        aesni_store_block128_aligned(bytes, key->hi);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    *cursor = '\0';
    return AESNI_SUCCESS;
}

AesNI_StatusCode aesni_aes128_print_key(
    const AesNI_Aes128_Key* key,
    AesNI_ErrorDetails* err_details)
{
    return aesni_aes_print_block(&key->key, err_details);
}

AesNI_StatusCode aesni_aes192_print_key(
    const AesNI_Aes192_Key* key,
    AesNI_ErrorDetails* err_details)
{
    assert(key);

    if (key == NULL)
        return aesni_error_null_argument(err_details, "key");

    AesNI_StatusCode ec = AESNI_SUCCESS;
    AesNI_Aes192_KeyString str;

    if (aesni_is_error(ec = aesni_aes192_format_key(&str, key, err_details)))
        return ec;

    printf("%s\n", str.str);
    return ec;
}

AesNI_StatusCode aesni_aes256_print_key(
    const AesNI_Aes256_Key* key,
    AesNI_ErrorDetails* err_details)
{
    assert(key);

    if (key == NULL)
        return aesni_error_null_argument(err_details, "key");

    AesNI_StatusCode ec = AESNI_SUCCESS;
    AesNI_Aes256_KeyString str;

    if (aesni_is_error(ec = aesni_aes256_format_key(&str, key, err_details)))
        return ec;

    printf("%s\n", str.str);
    return ec;
}

AesNI_StatusCode aesni_aes128_parse_key(
    AesNI_Aes128_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_aes_parse_block(&dest->key, src, err_details);
}

AesNI_StatusCode aesni_aes192_parse_key(
    AesNI_Aes192_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aesni_error_null_argument(err_details, "src");

    const char* cursor = src;

    {
        __declspec(align(16)) unsigned char bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aesni_error_parse(err_details, src, "a 192-bit block");
            bytes[i] = (unsigned char) byte;
            cursor += n;
        }

        dest->lo = aesni_load_block128_aligned(bytes);
    }

    {
        __declspec(align(16)) unsigned char bytes[16];

        for (int i = 0; i < 8; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aesni_error_parse(err_details, src, "a 192-bit block");
            bytes[i] = (unsigned char) byte;
            cursor += n;
        }

        memset(bytes + 8, 0x00, 8);
        dest->hi = aesni_load_block128_aligned(bytes);
    }

    return AESNI_SUCCESS;
}

AesNI_StatusCode aesni_aes256_parse_key(
    AesNI_Aes256_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aesni_error_null_argument(err_details, "src");

    const char* cursor = src;

    {
        __declspec(align(16)) unsigned char bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aesni_error_parse(err_details, src, "a 256-bit block");
            bytes[i] = (unsigned char) byte;
            cursor += n;
        }

        dest->lo = aesni_load_block128_aligned(bytes);
    }

    {
        __declspec(align(16)) unsigned char bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
                return aesni_error_parse(err_details, src, "a 256-bit block");
            bytes[i] = (unsigned char) byte;
            cursor += n;
        }

        dest->hi = aesni_load_block128_aligned(bytes);
    }

    return AESNI_SUCCESS;
}

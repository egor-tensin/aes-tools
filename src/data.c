/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <intrin.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

AesNI_BlockString128 aesni_format_block128(AesNI_Block128* block)
{
    assert(block);

    AesNI_BlockString128 result;
    char *cursor = result.str;

    __declspec(align(16)) unsigned char bytes[16];
    aesni_store_block128_aligned(bytes, *block);

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", bytes[i]);

    *cursor = '\0';
    return result;
}

AesNI_BlockString192 aesni_format_block192(AesNI_Block192* block)
{
    assert(block);

    AesNI_BlockString192 result;
    char *cursor = result.str;

    {
        __declspec(align(16)) unsigned char bytes[16];
        aesni_store_block128_aligned(bytes, block->lo);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    {
        __declspec(align(16)) unsigned char bytes[16];
        aesni_store_block128_aligned(bytes, block->hi);

        for (int i = 0; i < 8; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    *cursor = '\0';
    return result;
}

AesNI_BlockString256 aesni_format_block256(AesNI_Block256* block)
{
    assert(block);

    AesNI_BlockString256 result;
    char *cursor = result.str;

    {
        __declspec(align(16)) unsigned char bytes[16];
        aesni_store_block128_aligned(bytes, block->lo);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    {
        __declspec(align(16)) unsigned char bytes[16];
        aesni_store_block128_aligned(bytes, block->hi);

        for (int i = 0; i < 16; ++i, cursor += 2)
            sprintf(cursor, "%02x", bytes[i]);
    }

    *cursor = '\0';
    return result;
}

AesNI_BlockMatrixString128 aesni_format_block128_as_matrix(AesNI_Block128* block)
{
    assert(block);

    AesNI_BlockMatrixString128 result;
    char* cursor = result.str;

    __declspec(align(16)) unsigned char bytes[4][4];
    aesni_store_block128_aligned(bytes, *block);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 3; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[3][i]);
    }

    *cursor = '\0';
    return result;
}

AesNI_BlockMatrixString192 aesni_format_block192_as_matrix(AesNI_Block192* block)
{
    assert(block);

    AesNI_BlockMatrixString192 result;
    char* cursor = result.str;

    __declspec(align(16)) unsigned char bytes[8][4];
    aesni_store_block128_aligned(bytes, block->lo);
    aesni_store_block128_aligned(bytes + 16, block->hi);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 5; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[5][i]);
    }

    *cursor = '\0';
    return result;
}

AesNI_BlockMatrixString256 aesni_format_block256_as_matrix(AesNI_Block256* block)
{
    assert(block);

    AesNI_BlockMatrixString256 result;
    char* cursor = result.str;

    __declspec(align(16)) unsigned char bytes[8][4];
    aesni_store_block128_aligned(bytes, block->lo);
    aesni_store_block128_aligned(bytes + 16, block->hi);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 7; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[7][i]);
    }

    *cursor = '\0';
    return result;
}

void aesni_print_block128(AesNI_Block128* block)
{
    assert(block);

    printf("%s\n", aesni_format_block128(block).str);
}

void aesni_print_block192(AesNI_Block192* block)
{
    assert(block);

    printf("%s\n", aesni_format_block192(block).str);
}

void aesni_print_block256(AesNI_Block256* block)
{
    assert(block);

    printf("%s\n", aesni_format_block256(block).str);
}

void aesni_print_block128_as_matrix(AesNI_Block128* block)
{
    assert(block);

    printf("%s", aesni_format_block128_as_matrix(block).str);
}

void aesni_print_block192_as_matrix(AesNI_Block192* block)
{
    assert(block);

    printf("%s", aesni_format_block192_as_matrix(block).str);
}

void aesni_print_block256_as_matrix(AesNI_Block256* block)
{
    assert(block);

    printf("%s", aesni_format_block256_as_matrix(block).str);
}

AesNI_StatusCode aesni_parse_block128(
    AesNI_Block128* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aesni_make_null_argument_error(err_details, "dest");
    if (src == NULL)
        return aesni_make_null_argument_error(err_details, "src");

    __declspec(align(16)) unsigned char bytes[16];

    for (int i = 0; i < 16; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(src, "%2x%n", &byte, &n) != 1)
            return aesni_make_parse_error(err_details, src);
        bytes[i] = (unsigned char) byte;
        src += n;
    }

    *dest = aesni_load_block128_aligned(bytes);

    return aesni_initialize_error_details(err_details);
}

AesNI_StatusCode aesni_parse_block192(
    AesNI_Block192* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aesni_make_null_argument_error(err_details, "dest");
    if (src == NULL)
        return aesni_make_null_argument_error(err_details, "src");

    {
        __declspec(align(16)) unsigned char bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(src, "%2x%n", &byte, &n) != 1)
                return aesni_make_parse_error(err_details, src);
            bytes[i] = (unsigned char) byte;
            src += n;
        }

        dest->lo = aesni_load_block128_aligned(bytes);
    }

    {
        __declspec(align(16)) unsigned char bytes[16];

        for (int i = 0; i < 8; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(src, "%2x%n", &byte, &n) != 1)
                return aesni_make_parse_error(err_details, src);
            bytes[i] = (unsigned char) byte;
            src += n;
        }

        memset(bytes + 8, 0x00, 8);
        dest->hi = aesni_load_block128_aligned(bytes);
    }

    return aesni_initialize_error_details(err_details);
}

AesNI_StatusCode aesni_parse_block256(
    AesNI_Block256* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aesni_make_null_argument_error(err_details, "dest");
    if (src == NULL)
        return aesni_make_null_argument_error(err_details, "src");

    {
        __declspec(align(16)) unsigned char bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(src, "%2x%n", &byte, &n) != 1)
                return aesni_make_parse_error(err_details, src);
            bytes[i] = (unsigned char) byte;
            src += n;
        }

        dest->lo = aesni_load_block128_aligned(bytes);
    }

    {
        __declspec(align(16)) unsigned char bytes[16];

        for (int i = 0; i < 16; ++i)
        {
            int n;
            unsigned int byte;
            if (sscanf(src, "%2x%n", &byte, &n) != 1)
                return aesni_make_parse_error(err_details, src);
            bytes[i] = (unsigned char) byte;
            src += n;
        }

        dest->hi = aesni_load_block128_aligned(bytes);
    }

    return aesni_initialize_error_details(err_details);
}

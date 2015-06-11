/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "aesni/all.h"

#include <intrin.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

AesNI_BlockString128 aesni_format_block128(AesNI_Block128* block)
{
    assert(block);

#if defined AESNI_LE_BLOCK_IO && AESNI_LE_BLOCK_IO
    return aesni_format_block128_le(block);
#else
    return aesni_format_block128_be(block);
#endif
}

AesNI_BlockString192 aesni_format_block192(AesNI_Block192* block)
{
    assert(block);

#if defined AESNI_LE_BLOCK_IO && AESNI_LE_BLOCK_IO
    return aesni_format_block192_le(block);
#else
    return aesni_format_block192_be(block);
#endif
}

AesNI_BlockString256 aesni_format_block256(AesNI_Block256* block)
{
    assert(block);

#if defined AESNI_LE_BLOCK_IO && AESNI_LE_BLOCK_IO
    return aesni_format_block256_le(block);
#else
    return aesni_format_block256_be(block);
#endif
}

AesNI_BlockString128 aesni_format_block128_le(AesNI_Block128* block)
{
    assert(block);

    AesNI_BlockString128 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) block + 15 - i));

    *cursor = '\0';
    return result;
}

AesNI_BlockString192 aesni_format_block192_le(AesNI_Block192* block)
{
    assert(block);

    AesNI_BlockString192 result;
    char *cursor = result.str;

    for (int i = 0; i < 8; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + 7 - i));
    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + 15 - i));

    *cursor = '\0';
    return result;
}

AesNI_BlockString256 aesni_format_block256_le(AesNI_Block256* block)
{
    assert(block);

    AesNI_BlockString256 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + 15 - i));
    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + 15 - i));

    *cursor = '\0';
    return result;
}

AesNI_BlockString128 aesni_format_block128_be(AesNI_Block128* block)
{
    assert(block);

    AesNI_BlockString128 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) block + i));

    *cursor = '\0';
    return result;
}

AesNI_BlockString192 aesni_format_block192_be(AesNI_Block192* block)
{
    assert(block);

    AesNI_BlockString192 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + i));
    for (int i = 0; i < 8; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + i));

    *cursor = '\0';
    return result;
}

AesNI_BlockString256 aesni_format_block256_be(AesNI_Block256* block)
{
    assert(block);

    AesNI_BlockString256 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + i));
    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + i));

    *cursor = '\0';
    return result;
}

AesNI_BlockMatrixString128 aesni_format_block128_as_matrix(AesNI_Block128* block)
{
    assert(block);

    return aesni_format_block128_be_as_matrix(block);
}

AesNI_BlockMatrixString192 aesni_format_block192_as_matrix(AesNI_Block192* block)
{
    assert(block);

    return aesni_format_block192_be_as_matrix(block);
}

AesNI_BlockMatrixString256 aesni_format_block256_as_matrix(AesNI_Block256* block)
{
    assert(block);

    return aesni_format_block256_be_as_matrix(block);
}

AesNI_BlockMatrixString128 aesni_format_block128_be_as_matrix(AesNI_Block128* block)
{
    assert(block);

    __declspec(align(16)) unsigned char bytes[4][4];
    AesNI_BlockMatrixString128 result;
    char* cursor = result.str;

    _mm_store_si128((AesNI_Block128*) bytes, *block);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 3; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[3][i]);
    }

    *cursor = '\0';
    return result;
}

AesNI_BlockMatrixString192 aesni_format_block192_be_as_matrix(AesNI_Block192* block)
{
    assert(block);

    __declspec(align(16)) unsigned char bytes[8][4];
    AesNI_BlockMatrixString192 result;
    char* cursor = result.str;

    _mm_store_si128((AesNI_Block128*) bytes, block->lo);
    _mm_store_si128((AesNI_Block128*) bytes + 1, block->hi);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 5; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[5][i]);
    }

    *cursor = '\0';
    return result;
}

AesNI_BlockMatrixString256 aesni_format_block256_be_as_matrix(AesNI_Block256* block)
{
    assert(block);

    __declspec(align(16)) unsigned char bytes[8][4];
    AesNI_BlockMatrixString256 result;
    char* cursor = result.str;

    _mm_store_si128((AesNI_Block128*) bytes, block->lo);
    _mm_store_si128((AesNI_Block128*) bytes + 1, block->hi);

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

void aesni_print_block128_le(AesNI_Block128* block)
{
    assert(block);

    printf("%s\n", aesni_format_block128_le(block).str);
}

void aesni_print_block192_le(AesNI_Block192* block)
{
    assert(block);

    printf("%s\n", aesni_format_block192_le(block).str);
}

void aesni_print_block256_le(AesNI_Block256* block)
{
    assert(block);

    printf("%s\n", aesni_format_block256_le(block).str);
}

void aesni_print_block128_be(AesNI_Block128* block)
{
    assert(block);

    printf("%s\n", aesni_format_block128_be(block).str);
}

void aesni_print_block192_be(AesNI_Block192* block)
{
    assert(block);

    printf("%s\n", aesni_format_block192_be(block).str);
}

void aesni_print_block256_be(AesNI_Block256* block)
{
    assert(block);

    printf("%s\n", aesni_format_block256_be(block).str);
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

void aesni_print_block128_be_as_matrix(AesNI_Block128* block)
{
    assert(block);

    printf("%s", aesni_format_block128_be_as_matrix(block).str);
}

void aesni_print_block192_be_as_matrix(AesNI_Block192* block)
{
    assert(block);

    printf("%s", aesni_format_block192_be_as_matrix(block).str);
}

void aesni_print_block256_be_as_matrix(AesNI_Block256* block)
{
    assert(block);

    printf("%s", aesni_format_block256_be_as_matrix(block).str);
}

int aesni_parse_block128(AesNI_Block128* block, const char* src)
{
    assert(block);
    assert(src);

#if defined AESNI_LE_BLOCK_IO && AESNI_LE_BLOCK_IO
    return aesni_parse_block128_le(block, src);
#else
    return aesni_parse_block128_be(block, src);
#endif
}

int aesni_parse_block192(AesNI_Block192* block, const char* src)
{
    assert(block);
    assert(src);

#if defined AESNI_LE_BLOCK_IO && AESNI_LE_BLOCK_IO
    return aesni_parse_block192_le(block, src);
#else
    return aesni_parse_block192_be(block, src);
#endif
}

int aesni_parse_block256(AesNI_Block256* block, const char* src)
{
    assert(block);
    assert(src);

#if defined AESNI_LE_BLOCK_IO && AESNI_LE_BLOCK_IO
    return aesni_parse_block256_le(block, src);
#else
    return aesni_parse_block256_be(block, src);
#endif
}

int aesni_parse_block128_le(AesNI_Block128* block, const char* src)
{
    assert(block);
    assert(src);

    int n, xs[4];
    if (sscanf(src, "%8x%8x%8x%8x%n", &xs[0], &xs[1], &xs[2], &xs[3], &n) != 4
        || n != strlen(src))
        return 1;
    *block = aesni_make_block128(xs[0], xs[1], xs[2], xs[3]);
    return 0;
}

int aesni_parse_block192_le(AesNI_Block192* block, const char* src)
{
    assert(block);
    assert(src);

    int n, xs[6];
    if (sscanf(src, "%8x%8x%8x%8x%8x%8x%n", &xs[0], &xs[1], &xs[2], &xs[3], &xs[4], &xs[5], &n) != 6
        || n != strlen(src))
        return 1;
    *block = aesni_make_block192(xs[0], xs[1], xs[2], xs[3], xs[4], xs[5]);
    return 0;
}

int aesni_parse_block256_le(AesNI_Block256* block, const char* src)
{
    assert(block);
    assert(src);

    int n, xs[8];
    if (sscanf(src, "%8x%8x%8x%8x%8x%8x%8x%8x%n", &xs[0], &xs[1], &xs[2], &xs[3], &xs[4], &xs[5], &xs[6], &xs[7], &n) != 8
        || n != strlen(src))
        return 1;
    *block = aesni_make_block256(xs[0], xs[1], xs[2], xs[3], xs[4], xs[5], xs[6], xs[7]);
    return 0;
}

int aesni_parse_block128_be(AesNI_Block128* block, const char* src)
{
    assert(block);
    assert(src);

    unsigned char bytes[16];

    for (int i = 0; i < 16; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(src, "%2x%n", &byte, &n) != 1)
            return 1;
        bytes[i] = (unsigned char) byte;
        src += n;
    }

    *block = _mm_loadu_si128((AesNI_Block128*) bytes);
    return 0;
}

int aesni_parse_block192_be(AesNI_Block192* block, const char* src)
{
    assert(block);
    assert(src);

    AesNI_Block128 lo, hi;
    unsigned char lo_bytes[16], hi_bytes[16] = { 0 };

    for (int i = 0; i < 16; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(src, "%2x%n", &byte, &n) != 1)
            return 1;
        lo_bytes[i] = (unsigned char) byte;
        src += n;
    }

    lo = _mm_loadu_si128((AesNI_Block128*) lo_bytes);

    for (int i = 0; i < 8; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(src, "%2x%n", &byte, &n) != 1)
            return 1;
        hi_bytes[i] = (unsigned char) byte;
        src += n;
    }

    hi = _mm_loadu_si128((AesNI_Block128*) hi_bytes);

    block->hi = hi;
    block->lo = lo;
    return 0;
}

int aesni_parse_block256_be(AesNI_Block256* block, const char* src)
{
    assert(block);
    assert(src);

    AesNI_Block128 lo, hi;
    unsigned char lo_bytes[16], hi_bytes[16];

    for (int i = 0; i < 16; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(src, "%2x%n", &byte, &n) != 1)
            return 1;
        lo_bytes[i] = (unsigned char) byte;
        src += n;
    }

    lo = _mm_loadu_si128((AesNI_Block128*) lo_bytes);

    for (int i = 0; i < 16; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(src, "%2x%n", &byte, &n) != 1)
            return 1;
        hi_bytes[i] = (unsigned char) byte;
        src += n;
    }

    hi = _mm_loadu_si128((AesNI_Block128*) hi_bytes);

    block->hi = hi;
    block->lo = lo;
    return 0;
}

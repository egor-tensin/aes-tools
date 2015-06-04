/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "aesni/all.h"

#include <intrin.h>

#include <stdio.h>
#include <string.h>

AesBlockString128 format_aes_block128(AesBlock128* block)
{
#if defined LIBAESNI_BE_IO_BY_DEFAULT && LIBAESNI_BE_IO_BY_DEFAULT
    return format_aes_block128_be(block);
#else
    return format_aes_block128_le(block);
#endif
}

AesBlockString192 format_aes_block192(AesBlock192* block)
{
#if defined LIBAESNI_BE_IO_BY_DEFAULT && LIBAESNI_BE_IO_BY_DEFAULT
    return format_aes_block192_be(block);
#else
    return format_aes_block192_le(block);
#endif
}

AesBlockString256 format_aes_block256(AesBlock256* block)
{
#if defined LIBAESNI_BE_IO_BY_DEFAULT && LIBAESNI_BE_IO_BY_DEFAULT
    return format_aes_block256_be(block);
#else
    return format_aes_block256_le(block);
#endif
}

AesBlockString128 format_aes_block128_le(AesBlock128* block)
{
    AesBlockString128 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) block + 15 - i));

    *cursor = '\0';
    return result;
}

AesBlockString192 format_aes_block192_le(AesBlock192* block)
{
    AesBlockString192 result;
    char *cursor = result.str;

    for (int i = 0; i < 8; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + 7 - i));
    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + 15 - i));

    *cursor = '\0';
    return result;
}

AesBlockString256 format_aes_block256_le(AesBlock256* block)
{
    AesBlockString256 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + 15 - i));
    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + 15 - i));

    *cursor = '\0';
    return result;
}

AesBlockString128 format_aes_block128_be(AesBlock128* block)
{
    AesBlockString128 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) block + i));

    *cursor = '\0';
    return result;
}

AesBlockString192 format_aes_block192_be(AesBlock192* block)
{
    AesBlockString192 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + i));
    for (int i = 0; i < 8; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + i));

    *cursor = '\0';
    return result;
}

AesBlockString256 format_aes_block256_be(AesBlock256* block)
{
    AesBlockString256 result;
    char *cursor = result.str;

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + i));
    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + i));

    *cursor = '\0';
    return result;
}

AesBlockMatrixString128 format_aes_block128_as_matrix(AesBlock128* block)
{
    return format_aes_block128_be_as_matrix(block);
}

AesBlockMatrixString192 format_aes_block192_as_matrix(AesBlock192* block)
{
    return format_aes_block192_be_as_matrix(block);
}

AesBlockMatrixString256 format_aes_block256_as_matrix(AesBlock256* block)
{
    return format_aes_block256_be_as_matrix(block);
}

AesBlockMatrixString128 format_aes_block128_be_as_matrix(AesBlock128* block)
{
    __declspec(align(16)) unsigned char bytes[4][4];
    AesBlockMatrixString128 result;
    char* cursor = result.str;

    _mm_store_si128((AesBlock128*) bytes, *block);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 3; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[3][i]);
    }

    *cursor = '\0';
    return result;
}

AesBlockMatrixString192 format_aes_block192_be_as_matrix(AesBlock192* block)
{
    __declspec(align(16)) unsigned char bytes[8][4];
    AesBlockMatrixString192 result;
    char* cursor = result.str;

    _mm_store_si128((AesBlock128*) bytes, block->lo);
    _mm_store_si128((AesBlock128*) bytes + 1, block->hi);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 5; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[5][i]);
    }

    *cursor = '\0';
    return result;
}

AesBlockMatrixString256 format_aes_block256_be_as_matrix(AesBlock256* block)
{
    __declspec(align(16)) unsigned char bytes[8][4];
    AesBlockMatrixString256 result;
    char* cursor = result.str;

    _mm_store_si128((AesBlock128*) bytes, block->lo);
    _mm_store_si128((AesBlock128*) bytes + 1, block->hi);

    for (int i = 0; i < 4; ++i, cursor += 3)
    {
        for (int j = 0; j < 7; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[7][i]);
    }

    *cursor = '\0';
    return result;
}

void print_aes_block128(AesBlock128* block)
{
    printf("%s\n", format_aes_block128(block).str);
}

void print_aes_block192(AesBlock192* block)
{
    printf("%s\n", format_aes_block192(block).str);
}

void print_aes_block256(AesBlock256* block)
{
    printf("%s\n", format_aes_block256(block).str);
}

void print_aes_block128_le(AesBlock128* block)
{
    printf("%s\n", format_aes_block128_le(block).str);
}

void print_aes_block192_le(AesBlock192* block)
{
    printf("%s\n", format_aes_block192_le(block).str);
}

void print_aes_block256_le(AesBlock256* block)
{
    printf("%s\n", format_aes_block256_le(block).str);
}

void print_aes_block128_be(AesBlock128* block)
{
    printf("%s\n", format_aes_block128_be(block).str);
}

void print_aes_block192_be(AesBlock192* block)
{
    printf("%s\n", format_aes_block192_be(block).str);
}

void print_aes_block256_be(AesBlock256* block)
{
    printf("%s\n", format_aes_block256_be(block).str);
}

void print_aes_block128_as_matrix(AesBlock128* block)
{
    printf("%s\n", format_aes_block128(block).str);
}

void print_aes_block192_as_matrix(AesBlock192* block)
{
    printf("%s\n", format_aes_block192(block).str);
}

void print_aes_block256_as_matrix(AesBlock256* block)
{
    printf("%s\n", format_aes_block256(block).str);
}

void print_aes_block128_be_as_matrix(AesBlock128* block)
{
    printf("%s", format_aes_block128_be_as_matrix(block).str);
}

void print_aes_block192_be_as_matrix(AesBlock192* block)
{
    printf("%s", format_aes_block192_be_as_matrix(block).str);
}

void print_aes_block256_be_as_matrix(AesBlock256* block)
{
    printf("%s", format_aes_block256_be_as_matrix(block).str);
}

int parse_aes_block128(AesBlock128* block, const char* src)
{
#if defined LIBAESNI_BE_IO_BY_DEFAULT && LIBAESNI_BE_IO_BY_DEFAULT
    return parse_aes_block128_be(block, src);
#else
    return parse_aes_block128_le(block, src);
#endif
}

int parse_aes_block192(AesBlock192* block, const char* src)
{
#if defined LIBAESNI_BE_IO_BY_DEFAULT && LIBAESNI_BE_IO_BY_DEFAULT
    return parse_aes_block192_be(block, src);
#else
    return parse_aes_block192_le(block, src);
#endif
}

int parse_aes_block256(AesBlock256* block, const char* src)
{
#if defined LIBAESNI_BE_IO_BY_DEFAULT && LIBAESNI_BE_IO_BY_DEFAULT
    return parse_aes_block256_be(block, src);
#else
    return parse_aes_block256_le(block, src);
#endif
}

int parse_aes_block128_le(AesBlock128* block, const char* src)
{
    int n, xs[4];
    if (sscanf(src, "%8x%8x%8x%8x%n", &xs[0], &xs[1], &xs[2], &xs[3], &n) != 4
        || n != strlen(src))
        return 1;
    *block = make_aes_block128(xs[0], xs[1], xs[2], xs[3]);
    return 0;
}

int parse_aes_block192_le(AesBlock192* block, const char* src)
{
    int n, xs[6];
    if (sscanf(src, "%8x%8x%8x%8x%8x%8x%n", &xs[0], &xs[1], &xs[2], &xs[3], &xs[4], &xs[5], &n) != 6
        || n != strlen(src))
        return 1;
    *block = make_aes_block192(xs[0], xs[1], xs[2], xs[3], xs[4], xs[5]);
    return 0;
}

int parse_aes_block256_le(AesBlock256* block, const char* src)
{
    int n, xs[8];
    if (sscanf(src, "%8x%8x%8x%8x%8x%8x%8x%8x%n", &xs[0], &xs[1], &xs[2], &xs[3], &xs[4], &xs[5], &xs[6], &xs[7], &n) != 8
        || n != strlen(src))
        return 1;
    *block = make_aes_block256(xs[0], xs[1], xs[2], xs[3], xs[4], xs[5], xs[6], xs[7]);
    return 0;
}

int parse_aes_block128_be(AesBlock128* block, const char* src)
{
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

    *block = _mm_loadu_si128((AesBlock128*) bytes);
    return 0;
}

int parse_aes_block192_be(AesBlock192* block, const char* src)
{
    AesBlock128 lo, hi;
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

    lo = _mm_loadu_si128((AesBlock128*) lo_bytes);

    for (int i = 0; i < 8; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(src, "%2x%n", &byte, &n) != 1)
            return 1;
        hi_bytes[i] = (unsigned char) byte;
        src += n;
    }

    hi = _mm_loadu_si128((AesBlock128*) hi_bytes);

    block->hi = hi;
    block->lo = lo;
    return 0;
}

int parse_aes_block256_be(AesBlock256* block, const char* src)
{
    AesBlock128 lo, hi;
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

    lo = _mm_loadu_si128((AesBlock128*) lo_bytes);

    for (int i = 0; i < 16; ++i)
    {
        int n;
        unsigned int byte;
        if (sscanf(src, "%2x%n", &byte, &n) != 1)
            return 1;
        hi_bytes[i] = (unsigned char) byte;
        src += n;
    }

    hi = _mm_loadu_si128((AesBlock128*) hi_bytes);

    block->hi = hi;
    block->lo = lo;
    return 0;
}

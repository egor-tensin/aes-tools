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

AesBlock128 make_aes_block128(int hi3, int hi2, int lo1, int lo0)
{
    return _mm_set_epi32(hi3, hi2, lo1, lo0);
}

AesBlock192 make_aes_block192(int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    AesBlock192 result;
    result.hi = make_aes_block128(  0,   0, hi5, hi4);
    result.lo = make_aes_block128(lo3, lo2, lo1, lo0);
    return result;
}

AesBlock256 make_aes_block256(int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    AesBlock256 result;
    result.hi = make_aes_block128(hi7, hi6, hi5, hi4);
    result.lo = make_aes_block128(lo3, lo2, lo1, lo0);
    return result;
}

AesBlockString128 format_aes_block128(AesBlock128* block)
{
    int i;
    char *cursor;
    AesBlockString128 result;

    for (i = 0, cursor = result.str; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) block + 15 - i));

    *cursor = '\0';
    return result;
}

AesBlockString192 format_aes_block192(AesBlock192* block)
{
    int i;
    AesBlockString192 result;
    char *cursor = result.str;

    for (i = 0; i < 8; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + 7 - i));
    for (i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + 15 - i));

    *cursor = '\0';
    return result;
}

AesBlockString256 format_aes_block256(AesBlock256* block)
{
    int i;
    AesBlockString256 result;
    char *cursor = result.str;

    for (i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + 15 - i));
    for (i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + 15 - i));

    *cursor = '\0';
    return result;
}

AesBlockString128 format_aes_block128_fips_style(AesBlock128* block)
{
    int i;
    char *cursor;
    AesBlockString128 result;

    for (i = 0, cursor = result.str; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) block + i));

    *cursor = '\0';
    return result;
}

AesBlockString192 format_aes_block192_fips_style(AesBlock192* block)
{
    int i;
    AesBlockString192 result;
    char *cursor = result.str;

    for (i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + i));
    for (i = 0; i < 8; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + i));

    *cursor = '\0';
    return result;
}

AesBlockString256 format_aes_block256_fips_style(AesBlock256* block)
{
    int i;
    AesBlockString256 result;
    char *cursor = result.str;

    for (i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->lo + i));
    for (i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", *((unsigned char*) &block->hi + i));

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

void print_aes_block128_fips_style(AesBlock128* block)
{
    printf("%s\n", format_aes_block128_fips_style(block).str);
}

void print_aes_block192_fips_style(AesBlock192* block)
{
    printf("%s\n", format_aes_block192_fips_style(block).str);
}

void print_aes_block256_fips_style(AesBlock256* block)
{
    printf("%s\n", format_aes_block256_fips_style(block).str);
}

void print_aes_block128_fips_matrix_style(AesBlock128* block)
{
    int i, j;
    __declspec(align(16)) unsigned char bytes[4][4];

    _mm_store_si128((AesBlock128*) bytes, *block);

    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 3; ++j)
            printf("%02x ", bytes[j][i]);
        printf("%02x\n", bytes[3][i]);
    }
}

void print_aes_block192_fips_matrix_style(AesBlock192* block)
{
    int i, j;
    __declspec(align(16)) unsigned char bytes[8][4];

    _mm_store_si128((AesBlock128*) bytes, block->lo);
    _mm_store_si128((AesBlock128*) bytes + 1, block->hi);

    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 5; ++j)
            printf("%02x ", bytes[j][i]);
        printf("%02x\n", bytes[5][i]);
    }
}

void print_aes_block256_fips_matrix_style(AesBlock256* block)
{
    int i, j;
    __declspec(align(16)) unsigned char bytes[8][4];

    _mm_store_si128((AesBlock128*) bytes, block->lo);
    _mm_store_si128((AesBlock128*) bytes + 1, block->hi);

    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 7; ++j)
            printf("%02x ", bytes[j][i]);
        printf("%02x\n", bytes[7][i]);
    }
}

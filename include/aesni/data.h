/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <emmintrin.h>

typedef __m128i AesBlock128;

typedef struct
{
    AesBlock128 hi;
    AesBlock128 lo;
}
AesBlock192;

typedef struct
{
    AesBlock128 hi;
    AesBlock128 lo;
}
AesBlock256;

AesBlock128 make_aes_block128(int hi3, int hi2, int lo1, int lo0);
AesBlock192 make_aes_block192(int hi5, int hi4, int lo3, int lo2, int lo1, int lo0);
AesBlock256 make_aes_block256(int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0);

typedef struct { char str[33]; } AesBlockString128;
typedef struct { char str[49]; } AesBlockString192;
typedef struct { char str[65]; } AesBlockString256;

AesBlockString128 format_aes_block128(AesBlock128*);
AesBlockString192 format_aes_block192(AesBlock192*);
AesBlockString256 format_aes_block256(AesBlock256*);

AesBlockString128 format_aes_block128_fips_style(AesBlock128*);
AesBlockString192 format_aes_block192_fips_style(AesBlock192*);
AesBlockString256 format_aes_block256_fips_style(AesBlock256*);

typedef struct { char str[49]; } AesBlockMatrixString128;
typedef struct { char str[73]; } AesBlockMatrixString192;
typedef struct { char str[97]; } AesBlockMatrixString256;

AesBlockMatrixString128 format_aes_block128_fips_matrix_style(AesBlock128*);
AesBlockMatrixString192 format_aes_block192_fips_matrix_style(AesBlock192*);
AesBlockMatrixString256 format_aes_block256_fips_matrix_style(AesBlock256*);

void print_aes_block128(AesBlock128*);
void print_aes_block192(AesBlock192*);
void print_aes_block256(AesBlock256*);

void print_aes_block128_fips_style(AesBlock128*);
void print_aes_block192_fips_style(AesBlock192*);
void print_aes_block256_fips_style(AesBlock256*);

void print_aes_block128_fips_matrix_style(AesBlock128*);
void print_aes_block192_fips_matrix_style(AesBlock192*);
void print_aes_block256_fips_matrix_style(AesBlock256*);

int parse_aes_block128(AesBlock128*, const char*);
int parse_aes_block192(AesBlock192*, const char*);
int parse_aes_block256(AesBlock256*, const char*);

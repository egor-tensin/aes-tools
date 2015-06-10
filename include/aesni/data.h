/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <emmintrin.h>
#include <tmmintrin.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef __m128i AesBlock128;

static __inline AesBlock128 load_aes_block128(const unsigned char* src)
{
    return _mm_loadu_si128((AesBlock128*) src);
}

static __inline void __fastcall store_aes_block128(AesBlock128 block,
                                                   unsigned char* dest)
{
    _mm_storeu_si128((AesBlock128*) dest, block);
}

static __inline AesBlock128 __fastcall make_aes_block128(int hi3, int hi2, int lo1, int lo0)
{
    return _mm_set_epi32(hi3, hi2, lo1, lo0);
}

typedef struct
{
    AesBlock128 hi;
    AesBlock128 lo;
}
AesBlock192;

static __inline AesBlock192 __fastcall make_aes_block192(int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    AesBlock192 result;
    result.hi = make_aes_block128(  0,   0, hi5, hi4);
    result.lo = make_aes_block128(lo3, lo2, lo1, lo0);
    return result;
}

typedef struct
{
    AesBlock128 hi;
    AesBlock128 lo;
}
AesBlock256;

static __inline AesBlock256 __fastcall make_aes_block256(int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    AesBlock256 result;
    result.hi = make_aes_block128(hi7, hi6, hi5, hi4);
    result.lo = make_aes_block128(lo3, lo2, lo1, lo0);
    return result;
}

typedef struct
{
    AesBlock128 keys[11];
}
Aes128KeySchedule;

typedef struct
{
    AesBlock128 keys[13];
}
Aes192KeySchedule;

typedef struct
{
    AesBlock128 keys[15];
}
Aes256KeySchedule;

static __inline AesBlock128 __fastcall aes128_reverse_byte_order(AesBlock128 block)
{
    return _mm_shuffle_epi8(block, make_aes_block128(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f));
}

static __inline AesBlock128 __fastcall aes128_le2be(AesBlock128 block)
{
    return aes128_reverse_byte_order(block);
}

static __inline AesBlock128 __fastcall aes128_be2le(AesBlock128 block)
{
    return aes128_reverse_byte_order(block);
}

typedef struct { char str[33]; } AesBlockString128;
typedef struct { char str[49]; } AesBlockString192;
typedef struct { char str[65]; } AesBlockString256;

AesBlockString128 format_aes_block128(AesBlock128*);
AesBlockString192 format_aes_block192(AesBlock192*);
AesBlockString256 format_aes_block256(AesBlock256*);

AesBlockString128 format_aes_block128_le(AesBlock128*);
AesBlockString192 format_aes_block192_le(AesBlock192*);
AesBlockString256 format_aes_block256_le(AesBlock256*);

AesBlockString128 format_aes_block128_be(AesBlock128*);
AesBlockString192 format_aes_block192_be(AesBlock192*);
AesBlockString256 format_aes_block256_be(AesBlock256*);

typedef struct { char str[49]; } AesBlockMatrixString128;
typedef struct { char str[73]; } AesBlockMatrixString192;
typedef struct { char str[97]; } AesBlockMatrixString256;

AesBlockMatrixString128 format_aes_block128_as_matrix(AesBlock128*);
AesBlockMatrixString192 format_aes_block192_as_matrix(AesBlock192*);
AesBlockMatrixString256 format_aes_block256_as_matrix(AesBlock256*);

AesBlockMatrixString128 format_aes_block128_be_as_matrix(AesBlock128*);
AesBlockMatrixString192 format_aes_block192_be_as_matrix(AesBlock192*);
AesBlockMatrixString256 format_aes_block256_be_as_matrix(AesBlock256*);

void print_aes_block128(AesBlock128*);
void print_aes_block192(AesBlock192*);
void print_aes_block256(AesBlock256*);

void print_aes_block128_le(AesBlock128*);
void print_aes_block192_le(AesBlock192*);
void print_aes_block256_le(AesBlock256*);

void print_aes_block128_be(AesBlock128*);
void print_aes_block192_be(AesBlock192*);
void print_aes_block256_be(AesBlock256*);

void print_aes_block128_as_matrix(AesBlock128*);
void print_aes_block192_as_matrix(AesBlock192*);
void print_aes_block256_as_matrix(AesBlock256*);

void print_aes_block128_be_as_matrix(AesBlock128*);
void print_aes_block192_be_as_matrix(AesBlock192*);
void print_aes_block256_be_as_matrix(AesBlock256*);

int parse_aes_block128(AesBlock128*, const char*);
int parse_aes_block192(AesBlock192*, const char*);
int parse_aes_block256(AesBlock256*, const char*);

int parse_aes_block128_le(AesBlock128*, const char*);
int parse_aes_block192_le(AesBlock192*, const char*);
int parse_aes_block256_le(AesBlock256*, const char*);

int parse_aes_block128_be(AesBlock128*, const char*);
int parse_aes_block192_be(AesBlock192*, const char*);
int parse_aes_block256_be(AesBlock256*, const char*);

#ifdef __cplusplus
}
#endif

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 * \brief Declares necessary data structures (for blocks, keys, etc.)
 *        and auxiliary IO functions.
 */

#pragma once

#include <emmintrin.h>
#include <tmmintrin.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef __m128i AesNI_Block128;

static __inline AesNI_Block128 aesni_load_block128(const void* src)
{
    return _mm_loadu_si128((AesNI_Block128*) src);
}

static __inline void __fastcall aesni_store_block128(
    void* dest, AesNI_Block128 block)
{
    _mm_storeu_si128((AesNI_Block128*) dest, block);
}

static __inline AesNI_Block128 __fastcall aesni_make_block128(int hi3, int hi2, int lo1, int lo0)
{
    return _mm_set_epi32(hi3, hi2, lo1, lo0);
}

typedef struct
{
    AesNI_Block128 hi;
    AesNI_Block128 lo;
}
AesNI_Block192;

static __inline AesNI_Block192 __fastcall aesni_make_block192(int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    AesNI_Block192 result;
    result.hi = aesni_make_block128(  0,   0, hi5, hi4);
    result.lo = aesni_make_block128(lo3, lo2, lo1, lo0);
    return result;
}

typedef struct
{
    AesNI_Block128 hi;
    AesNI_Block128 lo;
}
AesNI_Block256;

static __inline AesNI_Block256 __fastcall aesni_make_block256(int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    AesNI_Block256 result;
    result.hi = aesni_make_block128(hi7, hi6, hi5, hi4);
    result.lo = aesni_make_block128(lo3, lo2, lo1, lo0);
    return result;
}

typedef struct
{
    AesNI_Block128 keys[11];
}
AesNI_KeySchedule128;

typedef struct
{
    AesNI_Block128 keys[13];
}
AesNI_KeySchedule192;

typedef struct
{
    AesNI_Block128 keys[15];
}
AesNI_KeySchedule256;

static __inline AesNI_Block128 __fastcall aesni_reverse_byte_order128(AesNI_Block128 block)
{
    return _mm_shuffle_epi8(block, aesni_make_block128(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f));
}

static __inline AesNI_Block128 __fastcall aesni_le2be128(AesNI_Block128 block)
{
    return aesni_reverse_byte_order128(block);
}

static __inline AesNI_Block128 __fastcall aesni_be2le128(AesNI_Block128 block)
{
    return aesni_reverse_byte_order128(block);
}

typedef struct { char str[33]; } AesNI_BlockString128;
typedef struct { char str[49]; } AesNI_BlockString192;
typedef struct { char str[65]; } AesNI_BlockString256;

AesNI_BlockString128 aesni_format_block128(AesNI_Block128*);
AesNI_BlockString192 aesni_format_block192(AesNI_Block192*);
AesNI_BlockString256 aesni_format_block256(AesNI_Block256*);

AesNI_BlockString128 aesni_format_block128_le(AesNI_Block128*);
AesNI_BlockString192 aesni_format_block192_le(AesNI_Block192*);
AesNI_BlockString256 aesni_format_block256_le(AesNI_Block256*);

AesNI_BlockString128 aesni_format_block128_be(AesNI_Block128*);
AesNI_BlockString192 aesni_format_block192_be(AesNI_Block192*);
AesNI_BlockString256 aesni_format_block256_be(AesNI_Block256*);

typedef struct { char str[49]; } AesNI_BlockMatrixString128;
typedef struct { char str[73]; } AesNI_BlockMatrixString192;
typedef struct { char str[97]; } AesNI_BlockMatrixString256;

AesNI_BlockMatrixString128 aesni_format_block128_as_matrix(AesNI_Block128*);
AesNI_BlockMatrixString192 aesni_format_block192_as_matrix(AesNI_Block192*);
AesNI_BlockMatrixString256 aesni_format_block256_as_matrix(AesNI_Block256*);

AesNI_BlockMatrixString128 aesni_format_block128_be_as_matrix(AesNI_Block128*);
AesNI_BlockMatrixString192 aesni_format_block192_be_as_matrix(AesNI_Block192*);
AesNI_BlockMatrixString256 aesni_format_block256_be_as_matrix(AesNI_Block256*);

void aesni_print_block128(AesNI_Block128*);
void aesni_print_block192(AesNI_Block192*);
void aesni_print_block256(AesNI_Block256*);

void aesni_print_block128_le(AesNI_Block128*);
void aesni_print_block192_le(AesNI_Block192*);
void aesni_print_block256_le(AesNI_Block256*);

void aesni_print_block128_be(AesNI_Block128*);
void aesni_print_block192_be(AesNI_Block192*);
void aesni_print_block256_be(AesNI_Block256*);

void aesni_print_block128_as_matrix(AesNI_Block128*);
void aesni_print_block192_as_matrix(AesNI_Block192*);
void aesni_print_block256_as_matrix(AesNI_Block256*);

void aesni_print_block128_be_as_matrix(AesNI_Block128*);
void aesni_print_block192_be_as_matrix(AesNI_Block192*);
void aesni_print_block256_be_as_matrix(AesNI_Block256*);

int aesni_parse_block128(AesNI_Block128*, const char*);
int aesni_parse_block192(AesNI_Block192*, const char*);
int aesni_parse_block256(AesNI_Block256*, const char*);

int aesni_parse_block128_le(AesNI_Block128*, const char*);
int aesni_parse_block192_le(AesNI_Block192*, const char*);
int aesni_parse_block256_le(AesNI_Block256*, const char*);

int aesni_parse_block128_be(AesNI_Block128*, const char*);
int aesni_parse_block192_be(AesNI_Block192*, const char*);
int aesni_parse_block256_be(AesNI_Block256*, const char*);

#ifdef __cplusplus
}
#endif

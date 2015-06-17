/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 *
 * \brief Declares necessary data structures (for blocks, keys, etc.) and
 * auxiliary I/O functions.
 */

#pragma once

#include "error.h"

/**
 * \defgroup aesni_data Data
 * \brief Data structures and I/O functions
 * \ingroup aesni
 * \{
 */

#include <emmintrin.h>
#include <tmmintrin.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * \brief Represents a 128-bit block.
 */
typedef __m128i AesNI_Block128;

/**
 * \brief Loads a 128-bit block from a memory location.
 *
 * \param[in] src The pointer to a memory location. Must not be `NULL`.
 *
 * \return The loaded 128-bit block.
 */
static __inline AesNI_Block128 aesni_load_block128(const void* src)
{
    return _mm_loadu_si128((AesNI_Block128*) src);
}

/**
 * \brief Loads a 128-bit block from a 16-byte aligned memory location.
 *
 * \param[in] src The pointer to a 16-byte aligned memory location. Must not be `NULL`.
 *
 * \return The loaded 128-bit block.
 */
static __inline AesNI_Block128 aesni_load_block128_aligned(const void* src)
{
    return _mm_load_si128((AesNI_Block128*) src);
}

/**
 * \brief Stores a 128-bit block in a memory location.
 *
 * \param[out] dest The pointer to a memory location. Must not be `NULL`.
 *
 * \param[in] block The block to be stored.
 */
static __inline void __fastcall aesni_store_block128(
    void* dest,
    AesNI_Block128 block)
{
    _mm_storeu_si128((AesNI_Block128*) dest, block);
}

/**
 * \brief Stores a 128-bit block in a 16-byte aligned memory location.
 *
 * \param[out] dest The pointer to a 16-byte aligned memory location. Must not be `NULL`.
 *
 * \param[in] block The block to be stored.
 */
static __inline void __fastcall aesni_store_block128_aligned(
    void* dest,
    AesNI_Block128 block)
{
    _mm_store_si128((AesNI_Block128*) dest, block);
}

/**
 * \brief XORs two 128-bit blocks.
 *
 * \param[in] a The first XOR operand.
 * \param[in] b The second XOR operand.
 *
 * \return `a^b`.
 */
static __inline AesNI_Block128 __fastcall aesni_xor_block128(
    AesNI_Block128 a,
    AesNI_Block128 b)
{
    return _mm_xor_si128(a, b);
}

/**
 * \brief Builds a 128-bit block from four 4-byte values.
 *
 * Builds a 128-bit block like this:
 *
 * * dest[127:96] = hi3
 * * dest[95:64] = hi2
 * * dest[63:32] = lo1
 * * dest[31:0] = lo0
 *
 * \param[in] hi3 The most significant 4-byte value.
 * \param[in] hi2 The more significant 4-byte value.
 * \param[in] lo1 The less significant 4-byte value.
 * \param[in] lo0 The least significant 4-byte value.
 * \return The built 128-bit block.
 */
static __inline AesNI_Block128 __fastcall aesni_make_block128(
    int hi3, int hi2, int lo1, int lo0)
{
    return _mm_set_epi32(hi3, hi2, lo1, lo0);
}

/**
 * \brief Represents a 192-bit block.
 */
typedef struct
{
    AesNI_Block128 hi; ///< The most significant 64 bits.
    AesNI_Block128 lo; ///< The least significant 128 bits.
}
AesNI_Block192;

/**
 * \brief Builds a 192-bit block from six 4-byte values.
 *
 * Builds a 192-bit block like this:
 *
 * * dest[191:160] = hi5
 * * dest[159:128] = hi4
 * * dest[127:96] = lo3
 * * dest[95:64] = lo2
 * * dest[63:32] = lo1
 * * dest[31:0] = lo0
 *
 * \param[in] hi5 The most significant 4-byte value (bits 160--191).
 * \param[in] hi4 The more significant 4-byte value (bits 128--159).
 * \param[in] lo3 The 4-byte value to be stored in bits 96--127.
 * \param[in] lo2 The 4-byte value to be stored in bits 64--95.
 * \param[in] lo1 The less significant 4-byte value (bits 32--63).
 * \param[in] lo0 The least significant 4-byte value (bits 0--31).
 * \return The built 192-bit block.
 */
static __inline AesNI_Block192 __fastcall aesni_make_block192(
    int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    AesNI_Block192 result;
    result.hi = aesni_make_block128(0, 0, hi5, hi4);
    result.lo = aesni_make_block128(lo3, lo2, lo1, lo0);
    return result;
}

/**
 * \brief Represents a 256-bit block.
 */
typedef struct
{
    AesNI_Block128 hi; ///< The most significant 128 bits.
    AesNI_Block128 lo; ///< The least significant 128 bits.
}
AesNI_Block256;

/**
 * \brief Builds a 256-bit block from eight 4-byte values.
 *
 * Builds a 256-bit block like this:
 *
 * * dest[255:224] = hi7
 * * dest[223:192] = hi6
 * * dest[191:160] = hi5
 * * dest[159:128] = hi4
 * * dest[127:96] = lo3
 * * dest[95:64] = lo2
 * * dest[63:32] = lo1
 * * dest[31:0] = lo0
 *
 * \param[in] hi7 The 4-byte value to be stored in bits 224--255.
 * \param[in] hi6 The 4-byte value to be stored in bits 192--223.
 * \param[in] hi5 The 4-byte value to be stored in bits 160--191.
 * \param[in] hi4 The 4-byte value to be stored in bits 128--159.
 * \param[in] lo3 The 4-byte value to be stored in bits 96--127.
 * \param[in] lo2 The 4-byte value to be stored in bits 64--95.
 * \param[in] lo1 The 4-byte value to be stored in bits 32--63.
 * \param[in] lo0 The 4-byte value to be stored in bits 0--31.
 * \return The built 256-bit block.
 */
static __inline AesNI_Block256 __fastcall aesni_make_block256(
    int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
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

AesNI_StatusCode aesni_format_block128(AesNI_BlockString128*, const AesNI_Block128*, AesNI_ErrorDetails*);
AesNI_StatusCode aesni_format_block192(AesNI_BlockString192*, const AesNI_Block192*, AesNI_ErrorDetails*);
AesNI_StatusCode aesni_format_block256(AesNI_BlockString256*, const AesNI_Block256*, AesNI_ErrorDetails*);

typedef struct { char str[49]; } AesNI_BlockMatrixString128;
typedef struct { char str[73]; } AesNI_BlockMatrixString192;
typedef struct { char str[97]; } AesNI_BlockMatrixString256;

AesNI_StatusCode aesni_format_block128_as_matrix(AesNI_BlockMatrixString128*, const AesNI_Block128*, AesNI_ErrorDetails*);
AesNI_StatusCode aesni_format_block192_as_matrix(AesNI_BlockMatrixString192*, const AesNI_Block192*, AesNI_ErrorDetails*);
AesNI_StatusCode aesni_format_block256_as_matrix(AesNI_BlockMatrixString256*, const AesNI_Block256*, AesNI_ErrorDetails*);

AesNI_StatusCode aesni_print_block128(const AesNI_Block128*, AesNI_ErrorDetails*);
AesNI_StatusCode aesni_print_block192(const AesNI_Block192*, AesNI_ErrorDetails*);
AesNI_StatusCode aesni_print_block256(const AesNI_Block256*, AesNI_ErrorDetails*);

AesNI_StatusCode aesni_print_block128_as_matrix(const AesNI_Block128*, AesNI_ErrorDetails*);
AesNI_StatusCode aesni_print_block192_as_matrix(const AesNI_Block192*, AesNI_ErrorDetails*);
AesNI_StatusCode aesni_print_block256_as_matrix(const AesNI_Block256*, AesNI_ErrorDetails*);

AesNI_StatusCode aesni_parse_block128(
    AesNI_Block128* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_parse_block192(
    AesNI_Block192* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

/**
 * \brief Parses a 256-bit block, from the least significant to the most significant byte.
 *
 * The block is parsed from a hexadecimal number represented using the big endian notation.
 *
 * The source string may optionally start with "0x" or "0X".
 * Then 64 characters in the range [0-9a-fA-F] must follow.
 *
 * \param[out] dest The pointer to the parsed block. Must not be `NULL`.
 * \param[in] src The pointer to the source C string. Must not be `NULL`.
 * \param[out] err_details The error details structure.
 * \retval AESNI_SUCCESS If parsed successfully.
 * \retval AESNI_NULL_ARGUMENT_ERROR If either `dest` or `src` is `NULL`.
 * \retval AESNI_PARSE_ERROR If `src` couldn't be parsed as a valid 256-bit block.
 * \sa aesni_error_handling.
 */
AesNI_StatusCode aesni_parse_block256(
    AesNI_Block256* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

/**
 * \}
 */

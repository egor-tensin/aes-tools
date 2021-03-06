// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <emmintrin.h>
#include <tmmintrin.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * \brief Represents a 128-bit block.
 */
typedef __m128i AES_Block128;

/**
 * \brief Loads a 128-bit block from a memory location.
 *
 * \param[in] src The pointer to a memory location. Must not be `NULL`.
 *
 * \return The loaded 128-bit block.
 */
static __inline AES_Block128 aes_load_block128(const void* src)
{
    return _mm_loadu_si128((AES_Block128*) src);
}

/**
 * \brief Loads a 128-bit block from a 16-byte aligned memory location.
 *
 * \param[in] src The pointer to a 16-byte aligned memory location. Must not be `NULL`.
 *
 * \return The loaded 128-bit block.
 */
static __inline AES_Block128 aes_load_block128_aligned(const void* src)
{
    return _mm_load_si128((AES_Block128*) src);
}

/**
 * \brief Stores a 128-bit block in a memory location.
 *
 * \param[out] dest The pointer to a memory location. Must not be `NULL`.
 *
 * \param[in] block The block to be stored.
 */
static __inline void __fastcall aes_store_block128(
    void* dest,
    AES_Block128 block)
{
    _mm_storeu_si128((AES_Block128*) dest, block);
}

/**
 * \brief Stores a 128-bit block in a 16-byte aligned memory location.
 *
 * \param[out] dest The pointer to a 16-byte aligned memory location. Must not be `NULL`.
 *
 * \param[in] block The block to be stored.
 */
static __inline void __fastcall aes_store_block128_aligned(
    void* dest,
    AES_Block128 block)
{
    _mm_store_si128((AES_Block128*) dest, block);
}

/**
 * \brief XORs two 128-bit blocks.
 *
 * \param[in] a The first XOR operand.
 * \param[in] b The second XOR operand.
 *
 * \return `a^b`.
 */
static __inline AES_Block128 __fastcall aes_xor_block128(
    AES_Block128 a,
    AES_Block128 b)
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
 *
 * \return The built 128-bit block.
 */
static __inline AES_Block128 __fastcall aes_make_block128(int hi3, int hi2, int lo1, int lo0)
{
    return _mm_set_epi32(hi3, hi2, lo1, lo0);
}

static __inline AES_Block128 __fastcall aes_reverse_byte_order_block128(AES_Block128 block)
{
    return _mm_shuffle_epi8(block, aes_make_block128(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f));
}

static __inline AES_Block128 __fastcall aes_inc_block128(AES_Block128 x)
{
    return _mm_add_epi32(x, aes_make_block128(0, 0, 0, 1));
}

#ifdef __cplusplus
}
#endif

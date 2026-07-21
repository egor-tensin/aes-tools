// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <emmintrin.h>
#include <tmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef __m128i AES_Block;

static inline AES_Block aes_load_block(const void* src) {
    return _mm_loadu_si128((AES_Block*)src);
}

static inline AES_Block aes_load_block_aligned(const void* src) {
    return _mm_load_si128((AES_Block*)src);
}

static inline void __fastcall aes_store_block(void* dest, AES_Block block) {
    _mm_storeu_si128((AES_Block*)dest, block);
}

static inline void __fastcall aes_store_block_aligned(void* dest, AES_Block block) {
    _mm_store_si128((AES_Block*)dest, block);
}

static inline AES_Block __fastcall aes_xor_blocks(AES_Block a, AES_Block b) {
    return _mm_xor_si128(a, b);
}

/**
 * hi3 - The most significant 4-byte value.
 * hi2 - The more significant 4-byte value.
 * lo1 - The less significant 4-byte value.
 * lo0 - The least significant 4-byte value.
 */
static inline AES_Block __fastcall aes_make_block(int hi3, int hi2, int lo1, int lo0) {
    return _mm_set_epi32(hi3, hi2, lo1, lo0);
}

static inline AES_Block __fastcall aes_reverse_byte_order_in_block(AES_Block block) {
    return _mm_shuffle_epi8(block, aes_make_block(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f));
}

static inline AES_Block __fastcall aes_inc_block(AES_Block x) {
    x = aes_reverse_byte_order_in_block(x);
    x = _mm_add_epi32(x, aes_make_block(0, 0, 0, 1));
    x = aes_reverse_byte_order_in_block(x);
    return x;
}

#ifdef __cplusplus
}
#endif

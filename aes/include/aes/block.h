/*
 * Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#pragma once

#include "error.h"

#include <emmintrin.h>
#include <tmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef __m128i AES_Block;

/* hi3 - the most significant 4-byte value, lo0 - the least. */
static inline AES_Block aes_make_block(int hi3, int hi2, int lo1, int lo0) {
    return _mm_set_epi32(hi3, hi2, lo1, lo0);
}

static inline AES_Block aes_load_block(const void* src) {
    return _mm_loadu_si128((AES_Block*)src);
}

static inline AES_Block aes_load_block_aligned(const void* src) {
    return _mm_load_si128((AES_Block*)src);
}

static inline void aes_store_block(void* dest, AES_Block block) {
    _mm_storeu_si128((AES_Block*)dest, block);
}

static inline void aes_store_block_aligned(void* dest, AES_Block block) {
    _mm_store_si128((AES_Block*)dest, block);
}

static inline AES_Block aes_xor_blocks(AES_Block a, AES_Block b) {
    return _mm_xor_si128(a, b);
}

AES_Block aes_inc_block(AES_Block x);

typedef struct {
    char str[33];
} AES_BlockString;

typedef struct {
    char str[49];
} AES_BlockMatrixString;

AES_StatusCode aes_format_block(AES_BlockString*, const AES_Block*, AES_ErrorDetails*);

AES_StatusCode aes_format_block_as_matrix(
    AES_BlockMatrixString*,
    const AES_Block*,
    AES_ErrorDetails*
);

AES_StatusCode aes_parse_block(AES_Block* dest, const char* src, AES_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

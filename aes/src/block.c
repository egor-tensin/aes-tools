/*
 * Copyright (c) 2026 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <assert.h>
#include <emmintrin.h>
#include <stdio.h>
#include <string.h>
#include <tmmintrin.h>

static AES_Block reverse_byte_order(AES_Block block) {
    return _mm_shuffle_epi8(block, aes_make_block(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f));
}

AES_Block aes_inc_block(AES_Block x) {
    x = reverse_byte_order(x);
    x = _mm_add_epi32(x, aes_make_block(0, 0, 0, 1));
    x = reverse_byte_order(x);
    return x;
}

AES_StatusCode aes_format_block(
    AES_BlockString* str,
    const AES_Block* block,
    AES_ErrorDetails* err_details
) {
    assert(str);
    assert(block);

    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (block == NULL)
        return aes_error_null_argument(err_details, "block");

    char* cursor = str->str;

    AES_ALIGN(unsigned char, 16) bytes[16];
    aes_store_block_aligned(bytes, *block);

    for (int i = 0; i < 16; ++i, cursor += 2)
        sprintf(cursor, "%02x", bytes[i]);

    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes_format_block_as_matrix(
    AES_BlockMatrixString* str,
    const AES_Block* block,
    AES_ErrorDetails* err_details
) {
    assert(str);
    assert(block);

    if (str == NULL)
        return aes_error_null_argument(err_details, "str");
    if (block == NULL)
        return aes_error_null_argument(err_details, "block");

    char* cursor = str->str;

    AES_ALIGN(unsigned char, 16) bytes[4][4];
    aes_store_block_aligned(bytes, *block);

    for (int i = 0; i < 4; ++i, cursor += 3) {
        for (int j = 0; j < 3; ++j, cursor += 3)
            sprintf(cursor, "%02x ", bytes[j][i]);
        sprintf(cursor, "%02x\n", bytes[3][i]);
    }

    *cursor = '\0';
    return AES_SUCCESS;
}

AES_StatusCode aes_parse_block(AES_Block* dest, const char* src, AES_ErrorDetails* err_details) {
    assert(dest);
    assert(src);

    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    const char* cursor = src;

    AES_ALIGN(unsigned char, 16) bytes[16];

    for (int i = 0; i < 16; ++i) {
        int n;
        unsigned int byte;
        if (sscanf(cursor, "%2x%n", &byte, &n) != 1)
            return aes_error_parse(err_details, src, "a 128-bit block");
        bytes[i] = (unsigned char)byte;
        cursor += n;
    }

    *dest = aes_load_block_aligned(bytes);
    return AES_SUCCESS;
}

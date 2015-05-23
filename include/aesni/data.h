/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <emmintrin.h>

typedef __m128i AesBlock;

AesBlock make_aes_block(int highest, int high, int low, int lowest);

typedef AesBlock Aes128Key;

typedef struct
{
    AesBlock hi;
    AesBlock lo;
}
Aes192Key;

typedef struct
{
    AesBlock hi;
    AesBlock lo;
}
Aes256Key;

typedef struct
{
    unsigned char bytes[4][4];
}
AesState;

AesState aes_block_to_state(AesBlock);
AesBlock aes_state_to_block(AesState);

void print_aes_block(AesBlock);

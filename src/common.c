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

AesBlock make_aes_block(int highest, int high, int low, int lowest)
{
    return _mm_set_epi32(highest, high, low, lowest);
}

AesState aes_block_to_state(AesBlock block)
{
    AesState state;
    _mm_storeu_si128((__m128i*) &state.bytes, block);
    return state;
}

void print_aes_block(AesBlock block)
{
    int i, j;
    AesState state = aes_block_to_state(block);

    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 3; ++j)
            printf("%02x ", state.bytes[j][i]);
        printf("%02x\n", state.bytes[3][i]);
    }
}

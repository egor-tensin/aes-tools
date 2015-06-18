/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "error.hpp"

#include <aesni/all.h>

namespace aesni
{
    typedef AesNI_Block128 Block128;

    inline void make_block(Block128& dest, int hi3, int hi2, int lo1, int lo0)
    {
        dest = aesni_make_block128(hi3, hi2, lo1, lo0);
    }

    inline void load_block(Block128& dest, const void* src)
    {
        dest = aesni_load_block128(src);
    }

    inline void load_block_aligned(Block128& dest, const void* src)
    {
        dest = aesni_load_block128_aligned(src);
    }

    inline void store_block(void* dest, Block128& src)
    {
        aesni_store_block128(dest, src);
    }

    inline void store_block_aligned(void* dest, Block128& src)
    {
        aesni_store_block128_aligned(dest, src);
    }

    inline Block128 xor_block(Block128& a, Block128& b)
    {
        return aesni_xor_block128(a, b);
    }
}

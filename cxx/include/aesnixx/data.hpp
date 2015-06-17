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
}

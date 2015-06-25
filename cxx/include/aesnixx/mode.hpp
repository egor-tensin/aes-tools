/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <aesni/all.h>

#include <type_traits>

namespace aesni
{
    typedef AesNI_Mode Mode;

    template <Mode mode>
    struct ModeRequiresInitializationVector : public std::true_type
    { };

    template <>
    struct ModeRequiresInitializationVector<AESNI_ECB> : public std::false_type
    { };

    inline bool mode_requires_initialization_vector(Mode mode)
    {
        return mode != AESNI_ECB;
    }
}

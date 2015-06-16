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

#include <cstdlib>

#include <ostream>
#include <string>

namespace aesni
{
    typedef AesNI_Block128 Block128;
    typedef AesNI_Block192 Block192;
    typedef AesNI_Block256 Block256;

    typedef AesNI_KeySchedule128 KeySchedule128;
    typedef AesNI_KeySchedule192 KeySchedule192;
    typedef AesNI_KeySchedule256 KeySchedule256;

    template <typename KeyScheduleT>
    inline std::size_t get_number_of_keys(const KeyScheduleT& key_schedule)
    {
        return sizeof(key_schedule) / sizeof(Block128);
    }

    inline void make_block(Block128& dest, int hi3, int hi2, int lo1, int lo0)
    {
        dest = aesni_make_block128(hi3, hi2, lo1, lo0);
    }

    inline void make_block(Block192& dest, int hi5, int hi4, int hi3, int lo2, int lo1, int lo0)
    {
        dest = aesni_make_block192(hi5, hi4, hi3, lo2, lo1, lo0);
    }

    inline void make_block(Block256& dest, int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
    {
        dest = aesni_make_block256(hi7, hi6, hi5, hi4, lo3, lo2, lo1, lo0);
    }

    std::string to_string(const Block128& block)
    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &block, ErrorDetailsThrowsInDestructor());
        return std::string(str.str);
    }

    std::string to_string(const Block192& block)
    {
        AesNI_BlockString192 str;
        aesni_format_block192(&str, &block, ErrorDetailsThrowsInDestructor());
        return std::string(str.str);
    }

    std::string to_string(const Block256& block)
    {
        AesNI_BlockString256 str;
        aesni_format_block256(&str, &block, ErrorDetailsThrowsInDestructor());
        return std::string(str.str);
    }

    std::string to_matrix_string(const Block128& block)
    {
        AesNI_BlockMatrixString128 str;
        aesni_format_block128_as_matrix(&str, &block, ErrorDetailsThrowsInDestructor());
        return std::string(str.str);
    }

    std::string to_matrix_string(const Block192& block)
    {
        AesNI_BlockMatrixString192 str;
        aesni_format_block192_as_matrix(&str, &block, ErrorDetailsThrowsInDestructor());
        return std::string(str.str);
    }

    std::string to_matrix_string(const Block256& block)
    {
        AesNI_BlockMatrixString256 str;
        aesni_format_block256_as_matrix(&str, &block, ErrorDetailsThrowsInDestructor());
        return std::string(str.str);
    }
}

namespace
{
    std::ostream& operator<<(std::ostream& os, const aesni::Block128& block)
    {
        return os << aesni::to_string(block);
    }

    std::ostream& operator<<(std::ostream& os, const aesni::Block192& block)
    {
        return os << aesni::to_string(block);
    }

    std::ostream& operator<<(std::ostream& os, const aesni::Block256& block)
    {
        return os << aesni::to_string(block);
    }
}

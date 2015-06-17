/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "data.hpp"

#include <aesni/all.h>

#include <string>

#pragma once

namespace aesni
{
    namespace aes
    {
        typedef AesNI_Aes_Block Block;

        typedef AesNI_Aes128_Key Key128;
        typedef AesNI_Aes192_Key Key192;
        typedef AesNI_Aes256_Key Key256;

        inline void make_block(Block& dest, int hi3, int hi2, int lo1, int lo0)
        {
            aesni_aes_make_block(&dest, hi3, hi2, lo1, lo0);
        }

        inline void make_key(Key128& dest, int hi3, int hi2, int lo1, int lo0)
        {
            aesni_aes128_make_key(&dest, hi3, hi2, lo1, lo0);
        }

        inline void make_key(Key192& dest, int hi5, int hi4, int hi3, int lo2, int lo1, int lo0)
        {
            aesni_aes192_make_key(&dest, hi5, hi4, hi3, lo2, lo1, lo0);
        }

        inline void make_key(Key256& dest, int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
        {
            aesni_aes256_make_key(&dest, hi7, hi6, hi5, hi4, lo3, lo2, lo1, lo0);
        }

        std::string to_string(const Block& block)
        {
            AesNI_Aes_BlockString str;
            aesni_aes_format_block(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        std::string to_matrix_string(const Block& block)
        {
            AesNI_Aes_BlockMatrixString str;
            aesni_aes_format_block_as_matrix(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        inline void from_string(Block& dest, const char* src)
        {
            aesni_aes_parse_block(&dest, src, ErrorDetailsThrowsInDestructor());
        }

        inline void from_string(Block& dest, const std::string& src)
        {
            from_string(dest, src.c_str());
        }

        std::string to_string(const Key128& block)
        {
            AesNI_Aes128_KeyString str;
            aesni_aes128_format_key(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        std::string to_string(const Key192& block)
        {
            AesNI_Aes192_KeyString str;
            aesni_aes192_format_key(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        std::string to_string(const Key256& block)
        {
            AesNI_Aes256_KeyString str;
            aesni_aes256_format_key(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        inline void from_string(Key128& dest, const char* src)
        {
            aesni_aes128_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
        }

        inline void from_string(Key192& dest, const char* src)
        {
            aesni_aes192_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
        }

        inline void from_string(Key256& dest, const char* src)
        {
            aesni_aes256_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
        }

        inline void from_string(Key128& dest, const std::string& src)
        {
            return from_string(dest, src.c_str());
        }

        inline void from_string(Key192& dest, const std::string& src)
        {
            return from_string(dest, src.c_str());
        }

        inline void from_string(Key256& dest, const std::string& src)
        {
            return from_string(dest, src.c_str());
        }

        typedef AesNI_Aes128_RoundKeys RoundKeys128;
        typedef AesNI_Aes192_RoundKeys RoundKeys192;
        typedef AesNI_Aes256_RoundKeys RoundKeys256;

        template <typename RoundKeysT>
        inline std::size_t get_number_of_keys(const RoundKeysT& round_keys)
        {
            return sizeof(round_keys) / sizeof(Block128);
        }
    }
}

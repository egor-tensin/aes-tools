// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "algorithm.hpp"
#include "api.hpp"
#include "error.hpp"
#include "mode.hpp"

#include <aes/all.h>

#include <cstddef>

#include <string>

namespace aes
{
    namespace aes128
    {
        typedef AES_AES128_Block Block;
        typedef AES_AES128_RoundKeys RoundKeys;
        typedef AES_AES128_Key Key;
    }

    template <>
    struct Types<AES_AES128>
    {
        typedef aes128::Block Block;
        typedef aes128::RoundKeys RoundKeys;
        typedef aes128::Key Key;
    };

    template <>
    std::size_t get_number_of_rounds<AES_AES128>()
    {
        return 11;
    }

    template <>
    void from_string<AES_AES128>(aes128::Block& dest, const char* src)
    {
        aes_AES128_parse_block(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AES_AES128>(const aes128::Block& src)
    {
        AES_AES128_BlockString str;
        aes_AES128_format_block(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    std::string to_matrix_string<AES_AES128>(const aes128::Block& src)
    {
        AES_AES128_BlockMatrixString str;
        aes_AES128_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    void from_string<AES_AES128>(aes128::Key& dest, const char* src)
    {
        aes_AES128_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AES_AES128>(const aes128::Key& src)
    {
        AES_AES128_KeyString str;
        aes_AES128_format_key(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    inline void expand_key<AES_AES128>(
        const aes128::Key& key,
        aes128::RoundKeys& encryption_keys)
    {
        aes_AES128_expand_key(&key, &encryption_keys);
    }

    template <>
    inline void derive_decryption_keys<AES_AES128>(
        const aes128::RoundKeys& encryption_keys,
        aes128::RoundKeys& decryption_keys)
    {
        aes_AES128_derive_decryption_keys(
            &encryption_keys, &decryption_keys);
    }

    AESXX_ENCRYPT_BLOCK_ECB(AES128);
    AESXX_DECRYPT_BLOCK_ECB(AES128);
    AESXX_ENCRYPT_BLOCK_CBC(AES128);
    AESXX_DECRYPT_BLOCK_CBC(AES128);
    AESXX_ENCRYPT_BLOCK_CFB(AES128);
    AESXX_DECRYPT_BLOCK_CFB(AES128);
    AESXX_ENCRYPT_BLOCK_OFB(AES128);
    AESXX_DECRYPT_BLOCK_OFB(AES128);
    AESXX_ENCRYPT_BLOCK_CTR(AES128);
    AESXX_DECRYPT_BLOCK_CTR(AES128);

    namespace aes192
    {
        typedef AES_AES192_Block Block;
        typedef AES_AES192_RoundKeys RoundKeys;
        typedef AES_AES192_Key Key;
    }

    template <>
    struct Types<AES_AES192>
    {
        typedef aes192::Block Block;
        typedef aes192::RoundKeys RoundKeys;
        typedef aes192::Key Key;
    };

    template <>
    std::size_t get_number_of_rounds<AES_AES192>()
    {
        return 13;
    }

    template <>
    void from_string<AES_AES192>(aes192::Block& dest, const char* src)
    {
        aes_AES192_parse_block(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AES_AES192>(const aes192::Block& src)
    {
        AES_AES192_BlockString str;
        aes_AES192_format_block(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    std::string to_matrix_string<AES_AES192>(const aes192::Block& src)
    {
        AES_AES192_BlockMatrixString str;
        aes_AES192_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    void from_string<AES_AES192>(aes192::Key& dest, const char* src)
    {
        aes_AES192_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AES_AES192>(const aes192::Key& src)
    {
        AES_AES192_KeyString str;
        aes_AES192_format_key(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    inline void expand_key<AES_AES192>(
        const aes192::Key& key,
        aes192::RoundKeys& encryption_keys)
    {
        aes_AES192_expand_key(&key, &encryption_keys);
    }

    template <>
    inline void derive_decryption_keys<AES_AES192>(
        const aes192::RoundKeys& encryption_keys,
        aes192::RoundKeys& decryption_keys)
    {
        aes_AES192_derive_decryption_keys(
            &encryption_keys, &decryption_keys);
    }

    AESXX_ENCRYPT_BLOCK_ECB(AES192);
    AESXX_DECRYPT_BLOCK_ECB(AES192);
    AESXX_ENCRYPT_BLOCK_CBC(AES192);
    AESXX_DECRYPT_BLOCK_CBC(AES192);
    AESXX_ENCRYPT_BLOCK_CFB(AES192);
    AESXX_DECRYPT_BLOCK_CFB(AES192);
    AESXX_ENCRYPT_BLOCK_OFB(AES192);
    AESXX_DECRYPT_BLOCK_OFB(AES192);
    AESXX_ENCRYPT_BLOCK_CTR(AES192);
    AESXX_DECRYPT_BLOCK_CTR(AES192);

    namespace aes256
    {
        typedef AES_AES256_Block Block;
        typedef AES_AES256_RoundKeys RoundKeys;
        typedef AES_AES256_Key Key;
    }

    template <>
    struct Types<AES_AES256>
    {
        typedef aes256::Block Block;
        typedef aes256::RoundKeys RoundKeys;
        typedef aes256::Key Key;
    };

    template <>
    std::size_t get_number_of_rounds<AES_AES256>()
    {
        return 15;
    }

    template <>
    void from_string<AES_AES256>(aes256::Block& dest, const char* src)
    {
        aes_AES256_parse_block(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AES_AES256>(const aes256::Block& src)
    {
        AES_AES256_BlockString str;
        aes_AES256_format_block(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    std::string to_matrix_string<AES_AES256>(const aes256::Block& src)
    {
        AES_AES256_BlockMatrixString str;
        aes_AES256_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    void from_string<AES_AES256>(aes256::Key& dest, const char* src)
    {
        aes_AES256_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AES_AES256>(const aes256::Key& src)
    {
        AES_AES256_KeyString str;
        aes_AES256_format_key(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    inline void expand_key<AES_AES256>(
        const aes256::Key& key,
        aes256::RoundKeys& encryption_keys)
    {
        aes_AES256_expand_key(&key, &encryption_keys);
    }

    template <>
    inline void derive_decryption_keys<AES_AES256>(
        const aes256::RoundKeys& encryption_keys,
        aes256::RoundKeys& decryption_keys)
    {
        aes_AES256_derive_decryption_keys(
            &encryption_keys, &decryption_keys);
    }

    AESXX_ENCRYPT_BLOCK_ECB(AES256);
    AESXX_DECRYPT_BLOCK_ECB(AES256);
    AESXX_ENCRYPT_BLOCK_CBC(AES256);
    AESXX_DECRYPT_BLOCK_CBC(AES256);
    AESXX_ENCRYPT_BLOCK_CFB(AES256);
    AESXX_DECRYPT_BLOCK_CFB(AES256);
    AESXX_ENCRYPT_BLOCK_OFB(AES256);
    AESXX_DECRYPT_BLOCK_OFB(AES256);
    AESXX_ENCRYPT_BLOCK_CTR(AES256);
    AESXX_DECRYPT_BLOCK_CTR(AES256);
}

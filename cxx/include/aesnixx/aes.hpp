/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "algorithm.hpp"
#include "api.hpp"
#include "error.hpp"
#include "mode.hpp"

#include <aesni/all.h>

#include <cstddef>

#include <string>

namespace aesni
{
    namespace aes128
    {
        typedef AesNI_AES128_Block Block;
        typedef AesNI_AES128_RoundKeys RoundKeys;
        typedef AesNI_AES128_Key Key;
    }

    template <>
    struct Types<AESNI_AES128>
    {
        typedef aes128::Block Block;
        typedef aes128::RoundKeys RoundKeys;
        typedef aes128::Key Key;
    };

    template <>
    std::size_t get_number_of_rounds<AESNI_AES128>()
    {
        return 11;
    }

    template <>
    void from_string<AESNI_AES128>(aes128::Block& dest, const char* src)
    {
        aesni_AES128_parse_block(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AESNI_AES128>(const aes128::Block& src)
    {
        AesNI_AES128_BlockString str;
        aesni_AES128_format_block(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    std::string to_matrix_string<AESNI_AES128>(const aes128::Block& src)
    {
        AesNI_AES128_BlockMatrixString str;
        aesni_AES128_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    void from_string<AESNI_AES128>(aes128::Key& dest, const char* src)
    {
        aesni_AES128_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AESNI_AES128>(const aes128::Key& src)
    {
        AesNI_AES128_KeyString str;
        aesni_AES128_format_key(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    inline void expand_key<AESNI_AES128>(
        const aes128::Key& key,
        aes128::RoundKeys& encryption_keys)
    {
        aesni_AES128_expand_key(&key, &encryption_keys);
    }

    template <>
    inline void derive_decryption_keys<AESNI_AES128>(
        const aes128::RoundKeys& encryption_keys,
        aes128::RoundKeys& decryption_keys)
    {
        aesni_AES128_derive_decryption_keys(
            &encryption_keys, &decryption_keys);
    }

    AESNIXX_ENCRYPT_BLOCK_ECB(AES128);
    AESNIXX_DECRYPT_BLOCK_ECB(AES128);
    AESNIXX_ENCRYPT_BLOCK_CBC(AES128);
    AESNIXX_DECRYPT_BLOCK_CBC(AES128);
    AESNIXX_ENCRYPT_BLOCK_CFB(AES128);
    AESNIXX_DECRYPT_BLOCK_CFB(AES128);
    AESNIXX_ENCRYPT_BLOCK_OFB(AES128);
    AESNIXX_DECRYPT_BLOCK_OFB(AES128);
    AESNIXX_ENCRYPT_BLOCK_CTR(AES128);
    AESNIXX_DECRYPT_BLOCK_CTR(AES128);

    namespace aes192
    {
        typedef AesNI_AES192_Block Block;
        typedef AesNI_AES192_RoundKeys RoundKeys;
        typedef AesNI_AES192_Key Key;
    }

    template <>
    struct Types<AESNI_AES192>
    {
        typedef aes192::Block Block;
        typedef aes192::RoundKeys RoundKeys;
        typedef aes192::Key Key;
    };

    template <>
    std::size_t get_number_of_rounds<AESNI_AES192>()
    {
        return 13;
    }

    template <>
    void from_string<AESNI_AES192>(aes192::Block& dest, const char* src)
    {
        aesni_AES192_parse_block(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AESNI_AES192>(const aes192::Block& src)
    {
        AesNI_AES192_BlockString str;
        aesni_AES192_format_block(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    std::string to_matrix_string<AESNI_AES192>(const aes192::Block& src)
    {
        AesNI_AES192_BlockMatrixString str;
        aesni_AES192_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    void from_string<AESNI_AES192>(aes192::Key& dest, const char* src)
    {
        aesni_AES192_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AESNI_AES192>(const aes192::Key& src)
    {
        AesNI_AES192_KeyString str;
        aesni_AES192_format_key(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    inline void expand_key<AESNI_AES192>(
        const aes192::Key& key,
        aes192::RoundKeys& encryption_keys)
    {
        aesni_AES192_expand_key(&key, &encryption_keys);
    }

    template <>
    inline void derive_decryption_keys<AESNI_AES192>(
        const aes192::RoundKeys& encryption_keys,
        aes192::RoundKeys& decryption_keys)
    {
        aesni_AES192_derive_decryption_keys(
            &encryption_keys, &decryption_keys);
    }

    AESNIXX_ENCRYPT_BLOCK_ECB(AES192);
    AESNIXX_DECRYPT_BLOCK_ECB(AES192);
    AESNIXX_ENCRYPT_BLOCK_CBC(AES192);
    AESNIXX_DECRYPT_BLOCK_CBC(AES192);
    AESNIXX_ENCRYPT_BLOCK_CFB(AES192);
    AESNIXX_DECRYPT_BLOCK_CFB(AES192);
    AESNIXX_ENCRYPT_BLOCK_OFB(AES192);
    AESNIXX_DECRYPT_BLOCK_OFB(AES192);
    AESNIXX_ENCRYPT_BLOCK_CTR(AES192);
    AESNIXX_DECRYPT_BLOCK_CTR(AES192);

    namespace aes256
    {
        typedef AesNI_AES256_Block Block;
        typedef AesNI_AES256_RoundKeys RoundKeys;
        typedef AesNI_AES256_Key Key;
    }

    template <>
    struct Types<AESNI_AES256>
    {
        typedef aes256::Block Block;
        typedef aes256::RoundKeys RoundKeys;
        typedef aes256::Key Key;
    };

    template <>
    std::size_t get_number_of_rounds<AESNI_AES256>()
    {
        return 15;
    }

    template <>
    void from_string<AESNI_AES256>(aes256::Block& dest, const char* src)
    {
        aesni_AES256_parse_block(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AESNI_AES256>(const aes256::Block& src)
    {
        AesNI_AES256_BlockString str;
        aesni_AES256_format_block(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    std::string to_matrix_string<AESNI_AES256>(const aes256::Block& src)
    {
        AesNI_AES256_BlockMatrixString str;
        aesni_AES256_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    void from_string<AESNI_AES256>(aes256::Key& dest, const char* src)
    {
        aesni_AES256_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
    }

    template <>
    std::string to_string<AESNI_AES256>(const aes256::Key& src)
    {
        AesNI_AES256_KeyString str;
        aesni_AES256_format_key(&str, &src, ErrorDetailsThrowsInDestructor());
        return { str.str };
    }

    template <>
    inline void expand_key<AESNI_AES256>(
        const aes256::Key& key,
        aes256::RoundKeys& encryption_keys)
    {
        aesni_AES256_expand_key(&key, &encryption_keys);
    }

    template <>
    inline void derive_decryption_keys<AESNI_AES256>(
        const aes256::RoundKeys& encryption_keys,
        aes256::RoundKeys& decryption_keys)
    {
        aesni_AES256_derive_decryption_keys(
            &encryption_keys, &decryption_keys);
    }

    AESNIXX_ENCRYPT_BLOCK_ECB(AES256);
    AESNIXX_DECRYPT_BLOCK_ECB(AES256);
    AESNIXX_ENCRYPT_BLOCK_CBC(AES256);
    AESNIXX_DECRYPT_BLOCK_CBC(AES256);
    AESNIXX_ENCRYPT_BLOCK_CFB(AES256);
    AESNIXX_DECRYPT_BLOCK_CFB(AES256);
    AESNIXX_ENCRYPT_BLOCK_OFB(AES256);
    AESNIXX_DECRYPT_BLOCK_OFB(AES256);
    AESNIXX_ENCRYPT_BLOCK_CTR(AES256);
    AESNIXX_DECRYPT_BLOCK_CTR(AES256);
}

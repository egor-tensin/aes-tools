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
#include <string_view>

namespace aes {
namespace aes128 {

typedef AES_Block Block;
typedef AES128_RoundKeys RoundKeys;
typedef AES128_Key Key;

} // namespace aes128

template <>
struct Types<AES_AES128> {
    typedef aes128::Block Block;
    typedef aes128::RoundKeys RoundKeys;
    typedef aes128::Key Key;
};

template <>
inline void from_string<AES_AES128>(aes128::Block& dest, std::string_view src) {
    aes_parse_block(&dest, src.data(), ErrorDetailsThrowsInDestructor{});
}

template <>
inline std::string to_string<AES_AES128>(const aes128::Block& src) {
    AES128_BlockString str;
    aes_format_block(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline std::string to_matrix_string<AES_AES128>(const aes128::Block& src) {
    AES128_BlockMatrixString str;
    aes_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline void from_string<AES_AES128>(aes128::Key& dest, std::string_view src) {
    aes128_parse_key(&dest, src.data(), ErrorDetailsThrowsInDestructor{});
}

template <>
inline std::string to_string<AES_AES128>(const aes128::Key& src) {
    AES128_KeyString str;
    aes128_format_key(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline void expand_key<AES_AES128>(const aes128::Key& key, aes128::RoundKeys& encryption_keys) {
    aes128_expand_key(&key, &encryption_keys);
}

template <>
inline void derive_decryption_keys<AES_AES128>(
    const aes128::RoundKeys& encryption_keys,
    aes128::RoundKeys& decryption_keys
) {
    aes128_derive_decryption_keys(&encryption_keys, &decryption_keys);
}

AESXX_ENCRYPT_BLOCK_ECB(128);
AESXX_DECRYPT_BLOCK_ECB(128);
AESXX_ENCRYPT_BLOCK_CBC(128);
AESXX_DECRYPT_BLOCK_CBC(128);
AESXX_ENCRYPT_BLOCK_CFB(128);
AESXX_DECRYPT_BLOCK_CFB(128);
AESXX_ENCRYPT_BLOCK_OFB(128);
AESXX_DECRYPT_BLOCK_OFB(128);
AESXX_ENCRYPT_BLOCK_CTR(128);
AESXX_DECRYPT_BLOCK_CTR(128);

namespace aes192 {

typedef AES_Block Block;
typedef AES192_RoundKeys RoundKeys;
typedef AES192_Key Key;

} // namespace aes192

template <>
struct Types<AES_AES192> {
    typedef aes192::Block Block;
    typedef aes192::RoundKeys RoundKeys;
    typedef aes192::Key Key;
};

template <>
inline void from_string<AES_AES192>(aes192::Block& dest, std::string_view src) {
    aes_parse_block(&dest, src.data(), ErrorDetailsThrowsInDestructor{});
}

template <>
inline std::string to_string<AES_AES192>(const aes192::Block& src) {
    AES192_BlockString str;
    aes_format_block(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline std::string to_matrix_string<AES_AES192>(const aes192::Block& src) {
    AES192_BlockMatrixString str;
    aes_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline void from_string<AES_AES192>(aes192::Key& dest, std::string_view src) {
    aes192_parse_key(&dest, src.data(), ErrorDetailsThrowsInDestructor{});
}

template <>
inline std::string to_string<AES_AES192>(const aes192::Key& src) {
    AES192_KeyString str;
    aes192_format_key(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline void expand_key<AES_AES192>(const aes192::Key& key, aes192::RoundKeys& encryption_keys) {
    aes192_expand_key(&key, &encryption_keys);
}

template <>
inline void derive_decryption_keys<AES_AES192>(
    const aes192::RoundKeys& encryption_keys,
    aes192::RoundKeys& decryption_keys
) {
    aes192_derive_decryption_keys(&encryption_keys, &decryption_keys);
}

AESXX_ENCRYPT_BLOCK_ECB(192);
AESXX_DECRYPT_BLOCK_ECB(192);
AESXX_ENCRYPT_BLOCK_CBC(192);
AESXX_DECRYPT_BLOCK_CBC(192);
AESXX_ENCRYPT_BLOCK_CFB(192);
AESXX_DECRYPT_BLOCK_CFB(192);
AESXX_ENCRYPT_BLOCK_OFB(192);
AESXX_DECRYPT_BLOCK_OFB(192);
AESXX_ENCRYPT_BLOCK_CTR(192);
AESXX_DECRYPT_BLOCK_CTR(192);

namespace aes256 {

typedef AES_Block Block;
typedef AES256_RoundKeys RoundKeys;
typedef AES256_Key Key;

} // namespace aes256

template <>
struct Types<AES_AES256> {
    typedef aes256::Block Block;
    typedef aes256::RoundKeys RoundKeys;
    typedef aes256::Key Key;
};

template <>
inline void from_string<AES_AES256>(aes256::Block& dest, std::string_view src) {
    aes_parse_block(&dest, src.data(), ErrorDetailsThrowsInDestructor{});
}

template <>
inline std::string to_string<AES_AES256>(const aes256::Block& src) {
    AES256_BlockString str;
    aes_format_block(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline std::string to_matrix_string<AES_AES256>(const aes256::Block& src) {
    AES256_BlockMatrixString str;
    aes_format_block_as_matrix(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline void from_string<AES_AES256>(aes256::Key& dest, std::string_view src) {
    aes256_parse_key(&dest, src.data(), ErrorDetailsThrowsInDestructor{});
}

template <>
inline std::string to_string<AES_AES256>(const aes256::Key& src) {
    AES256_KeyString str;
    aes256_format_key(&str, &src, ErrorDetailsThrowsInDestructor{});
    return {str.str};
}

template <>
inline void expand_key<AES_AES256>(const aes256::Key& key, aes256::RoundKeys& encryption_keys) {
    aes256_expand_key(&key, &encryption_keys);
}

template <>
inline void derive_decryption_keys<AES_AES256>(
    const aes256::RoundKeys& encryption_keys,
    aes256::RoundKeys& decryption_keys
) {
    aes256_derive_decryption_keys(&encryption_keys, &decryption_keys);
}

AESXX_ENCRYPT_BLOCK_ECB(256);
AESXX_DECRYPT_BLOCK_ECB(256);
AESXX_ENCRYPT_BLOCK_CBC(256);
AESXX_DECRYPT_BLOCK_CBC(256);
AESXX_ENCRYPT_BLOCK_CFB(256);
AESXX_DECRYPT_BLOCK_CFB(256);
AESXX_ENCRYPT_BLOCK_OFB(256);
AESXX_DECRYPT_BLOCK_OFB(256);
AESXX_ENCRYPT_BLOCK_CTR(256);
AESXX_DECRYPT_BLOCK_CTR(256);

} // namespace aes

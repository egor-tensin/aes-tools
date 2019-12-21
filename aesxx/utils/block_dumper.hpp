// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <aesxx/all.hpp>

#include <cstdlib>

#include <iostream>
#include <type_traits>

template <aes::Algorithm algorithm>
void dump_block(
    const char* header,
    const typename aes::Types<algorithm>::Block& block)
{
    std::cout << header << ": " << aes::to_string<algorithm>(block) << "\n";
    std::cout << aes::to_matrix_string<algorithm>(block) << "\n";
}

template <aes::Algorithm algorithm>
void dump_plaintext(const typename aes::Types<algorithm>::Block& block)
{
    dump_block<algorithm>("Plaintext", block);
}

template <aes::Algorithm algorithm>
void dump_key(const typename aes::Types<algorithm>::Key& key)
{
    std::cout << "Key: " << aes::to_string<algorithm>(key) << "\n\n";
}

template <aes::Algorithm algorithm>
void dump_ciphertext(const typename aes::Types<algorithm>::Block& ciphertext)
{
    dump_block<algorithm>("Ciphertext", ciphertext);
}

template <aes::Algorithm algorithm>
void dump_iv(const typename aes::Types<algorithm>::Block& iv)
{
    dump_block<algorithm>("Initialization vector", iv);
}

template <aes::Algorithm algorithm>
void dump_round_keys(
    const char* header,
    const typename aes::Types<algorithm>::RoundKeys& round_keys)
{
    std::cout << header << ":\n";
    for (std::size_t i = 0; i < aes::get_number_of_rounds<algorithm>(); ++i)
        std::cout << "\t[" << i << "]: " << aes::to_string<algorithm>(round_keys.keys[i]) << "\n";
    std::cout << "\n";
}

template <aes::Algorithm algorithm>
void dump_encryption_keys(const typename aes::Types<algorithm>::RoundKeys& round_keys)
{
    dump_round_keys<algorithm>("Encryption round keys", round_keys);
}

template <aes::Algorithm algorithm>
void dump_decryption_keys(const typename aes::Types<algorithm>::RoundKeys& round_keys)
{
    dump_round_keys<algorithm>("Decryption round keys", round_keys);
}

template <aes::Algorithm algorithm, aes::Mode mode>
void dump_wrapper(const aes::EncryptWrapper<algorithm, mode>& wrapper)
{
    dump_encryption_keys<algorithm>(wrapper.encryption_keys);
}

template <aes::Algorithm algorithm, aes::Mode mode>
void dump_wrapper(const aes::DecryptWrapper<algorithm, mode>& wrapper)
{
    dump_decryption_keys<algorithm>(wrapper.decryption_keys);
}

template <aes::Algorithm algorithm, aes::Mode mode,
          typename std::enable_if<aes::ModeRequiresInitVector<mode>::value>::type* = nullptr>
void dump_next_iv(const aes::EncryptWrapper<algorithm, mode>& wrapper)
{
    dump_block<algorithm>("Next initialization vector", wrapper.iv);
}

template <aes::Algorithm algorithm, aes::Mode mode,
          typename std::enable_if<!aes::ModeRequiresInitVector<mode>::value>::type* = nullptr>
void dump_next_iv(const aes::EncryptWrapper<algorithm, mode>&)
{ }

template <aes::Algorithm algorithm, aes::Mode mode,
          typename std::enable_if<aes::ModeRequiresInitVector<mode>::value>::type* = nullptr>
void dump_next_iv(const aes::DecryptWrapper<algorithm, mode>& wrapper)
{
    dump_block<algorithm>("Next initialization vector", wrapper.iv);
}

template <aes::Algorithm algorithm, aes::Mode mode,
          typename std::enable_if<!aes::ModeRequiresInitVector<mode>::value>::type* = nullptr>
void dump_next_iv(const aes::DecryptWrapper<algorithm, mode>&)
{ }

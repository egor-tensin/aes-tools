// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <aesxx/all.hpp>

#include <cstdlib>
#include <format>
#include <iostream>
#include <string_view>
#include <type_traits>

template <aes::Algorithm algorithm>
void dump_block(std::string_view header, const typename aes::Types<algorithm>::Block& block) {
    std::cout << std::format("{}: {}\n", header, aes::to_string<algorithm>(block));
    std::cout << std::format("{}\n", aes::to_matrix_string<algorithm>(block));
}

template <aes::Algorithm algorithm>
void dump_plaintext(const typename aes::Types<algorithm>::Block& block) {
    dump_block<algorithm>("Plaintext", block);
}

template <aes::Algorithm algorithm>
void dump_key(const typename aes::Types<algorithm>::Key& key) {
    std::cout << std::format("Key: {}\n\n", aes::to_string<algorithm>(key));
}

template <aes::Algorithm algorithm>
void dump_ciphertext(const typename aes::Types<algorithm>::Block& ciphertext) {
    dump_block<algorithm>("Ciphertext", ciphertext);
}

template <aes::Algorithm algorithm>
void dump_iv(const typename aes::Types<algorithm>::Block& iv) {
    dump_block<algorithm>("Initialization vector", iv);
}

template <aes::Algorithm algorithm>
void dump_round_keys(
    const char* header,
    const typename aes::Types<algorithm>::RoundKeys& round_keys
) {
    std::cout << std::format("{}:\n", header);
    for (std::size_t i = 0; i < aes::get_number_of_rounds<algorithm>(); ++i)
        std::cout << std::format("\t[{}]: {}\n", i, aes::to_string<algorithm>(round_keys.keys[i]));
    std::cout << "\n";
}

template <aes::Algorithm algorithm>
void dump_encryption_keys(const typename aes::Types<algorithm>::RoundKeys& round_keys) {
    dump_round_keys<algorithm>("Encryption round keys", round_keys);
}

template <aes::Algorithm algorithm>
void dump_decryption_keys(const typename aes::Types<algorithm>::RoundKeys& round_keys) {
    dump_round_keys<algorithm>("Decryption round keys", round_keys);
}

template <aes::Algorithm algorithm, aes::Mode mode>
void dump_wrapper(const aes::EncryptWrapper<algorithm, mode>& wrapper) {
    dump_encryption_keys<algorithm>(wrapper.encryption_keys);
}

template <aes::Algorithm algorithm, aes::Mode mode>
void dump_wrapper(const aes::DecryptWrapper<algorithm, mode>& wrapper) {
    dump_decryption_keys<algorithm>(wrapper.decryption_keys);
}

template <aes::Algorithm algorithm, aes::Mode mode>
void dump_next_iv(const aes::EncryptWrapper<algorithm, mode>& wrapper) {
    if constexpr (aes::mode_requires_init_vector(mode)) {
        dump_block<algorithm>("Next initialization vector", wrapper.iv);
    }
}

template <aes::Algorithm algorithm, aes::Mode mode>
void dump_next_iv(const aes::DecryptWrapper<algorithm, mode>& wrapper) {
    if constexpr (aes::mode_requires_init_vector(mode)) {
        dump_block<algorithm>("Next initialization vector", wrapper.iv);
    }
}

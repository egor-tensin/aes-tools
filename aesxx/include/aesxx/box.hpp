// Copyright (c) 2015 Egor Tensin <egor@tensin.name>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "algorithm.hpp"
#include "data.hpp"
#include "error.hpp"
#include "mode.hpp"

#include <aes/all.h>

#include <cstddef>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace aes {

class Box {
public:
    using Key = AES_Key;

    /*
    static std::string format_key(const Key& src, Algorithm algorithm) {
        AES_KeyString str;
        aes_format_key(&str, algorithm, &src, ErrorDetailsThrowsInDestructor{});
        return reinterpret_cast<const char*>(&str);
    }
    */

    static void parse_key(Key& dest, Algorithm algorithm, std::string_view src) {
        aes_parse_key(algorithm, &dest, src.data(), ErrorDetailsThrowsInDestructor{});
    }

    Box(Algorithm algorithm, const Key& key, Mode mode, const std::optional<Block>& iv) {
        aes_box_init(
            &impl, algorithm, &key, mode, iv ? iv->ptr() : NULL, ErrorDetailsThrowsInDestructor{}
        );
    }

    Algorithm get_algorithm() const {
        return impl.algorithm;
    }

    Mode get_mode() const {
        return impl.mode;
    }

    void encrypt_block(const Block& plaintext, Block& ciphertext) {
        dump_block("Plaintext", plaintext);
        aes_box_encrypt_block(
            &impl, plaintext.ptr(), ciphertext.ptr(), ErrorDetailsThrowsInDestructor{}
        );
        dump_block("Ciphertext", ciphertext);
    }

    void decrypt_block(const Block& ciphertext, Block& plaintext) {
        dump_block("Ciphertext", ciphertext);
        aes_box_decrypt_block(
            &impl, ciphertext.ptr(), plaintext.ptr(), ErrorDetailsThrowsInDestructor{}
        );
        dump_block("Plaintext", plaintext);
    }

    std::vector<unsigned char> encrypt_buffer(const void* src_buf, std::size_t src_size) {
        std::size_t dest_size = 0;

        aes_box_encrypt_buffer(
            &impl, src_buf, src_size, nullptr, &dest_size, aes::ErrorDetailsThrowsInDestructor{}
        );

        std::vector<unsigned char> dest_buf;
        dest_buf.resize(dest_size);

        aes_box_encrypt_buffer(
            &impl,
            src_buf,
            src_size,
            dest_buf.data(),
            &dest_size,
            aes::ErrorDetailsThrowsInDestructor{}
        );

        dest_buf.resize(dest_size);
        return dest_buf;
    }

    std::vector<unsigned char> decrypt_buffer(const void* src_buf, std::size_t src_size) {
        std::size_t dest_size = 0;

        aes_box_decrypt_buffer(
            &impl, src_buf, src_size, nullptr, &dest_size, aes::ErrorDetailsThrowsInDestructor{}
        );

        std::vector<unsigned char> dest_buf;
        dest_buf.resize(dest_size);

        aes_box_decrypt_buffer(
            &impl,
            src_buf,
            src_size,
            dest_buf.data(),
            &dest_size,
            aes::ErrorDetailsThrowsInDestructor{}
        );

        dest_buf.resize(dest_size);
        return dest_buf;
    }

private:
    void dump_block(std::string_view header, const Block& block) {
        if (verbose > 0)
            std::cout << std::format("{}: {}\n", header, block.to_string());
        if (verbose > 1)
            std::cout << std::format("{}\n", block.to_matrix_string());
    }

    AES_Box impl;
    int verbose = 0;
};

} // namespace aes

// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "algorithm.hpp"
#include "error.hpp"
#include "mode.hpp"

#include <aes/all.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace aes {

class Box {
public:
    typedef AES_Block Block;
    typedef AES_BoxKey Key;

    static std::string format_key(const Key& src, Algorithm algorithm) {
        AES_BoxKeyString str;
        aes_box_format_key(&str, algorithm, &src, ErrorDetailsThrowsInDestructor{});
        return reinterpret_cast<const char*>(&str);
    }

    static std::string format_block(const Block& src) {
        AES_BlockString str;
        aes_format_block(&str, &src, ErrorDetailsThrowsInDestructor{});
        return reinterpret_cast<const char*>(&str);
    }

    static void parse_block(Block& dest, std::string_view src) {
        aes_parse_block(&dest, src.data(), ErrorDetailsThrowsInDestructor{});
    }

    static void parse_key(Key& dest, Algorithm algorithm, std::string_view src) {
        aes_box_parse_key(&dest, algorithm, src.data(), ErrorDetailsThrowsInDestructor{});
    }

    Box(Algorithm algorithm, const Key& key) {
        aes_box_init(&impl, algorithm, &key, AES_ECB, nullptr, ErrorDetailsThrowsInDestructor{});
    }

    Box(Algorithm algorithm, const Key& key, Mode mode, const Block& iv) {
        aes_box_init(&impl, algorithm, &key, mode, &iv, ErrorDetailsThrowsInDestructor{});
    }

    void encrypt_block(const Block& plaintext, Block& ciphertext) {
        aes_box_encrypt_block(&impl, &plaintext, &ciphertext, ErrorDetailsThrowsInDestructor{});
    }

    void decrypt_block(const Block& ciphertext, Block& plaintext) {
        aes_box_decrypt_block(&impl, &ciphertext, &plaintext, ErrorDetailsThrowsInDestructor{});
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

    std::string format_key(const Key& src) {
        return format_key(src, get_algorithm());
    }

    void parse_key(Key& dest, std::string_view src) {
        parse_key(dest, get_algorithm(), src);
    }

    Algorithm get_algorithm() const {
        return impl.algorithm;
    }

    Mode get_mode() const {
        return impl.mode;
    }

private:
    Key key;

    AES_Box impl;
};

} // namespace aes

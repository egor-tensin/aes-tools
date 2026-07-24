// Copyright (c) 2015 Egor Tensin <egor@tensin.name>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "algorithm.hpp"
#include "block.hpp"
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

    static void parse_key(Key& dest, Algorithm algorithm, std::string_view src) {
        aes_parse_key(algorithm, &dest, src.data(), ErrorDetailsThrowsInDestructor{});
    }

    Box(Algorithm algorithm,
        const Key& key,
        Mode mode,
        const std::optional<Block>& iv,
        bool verbose = false)
        : verbose{verbose} {
        aes_box_init(
            &impl, algorithm, &key, mode, iv ? iv->ptr() : NULL, ErrorDetailsThrowsInDestructor{}
        );
        dump_key(key);
    }

    Algorithm get_algorithm() const {
        return impl.algorithm;
    }

    Mode get_mode() const {
        return impl.mode;
    }

    void encrypt_block(const Block& plaintext, Block& ciphertext) {
        dump_iv();
        dump_plaintext(plaintext);
        aes_box_encrypt_block(
            &impl, plaintext.ptr(), ciphertext.ptr(), ErrorDetailsThrowsInDestructor{}
        );
        dump_ciphertext(ciphertext);
    }

    void decrypt_block(const Block& ciphertext, Block& plaintext) {
        dump_iv();
        dump_ciphertext(ciphertext);
        aes_box_decrypt_block(
            &impl, ciphertext.ptr(), plaintext.ptr(), ErrorDetailsThrowsInDestructor{}
        );
        dump_plaintext(plaintext);
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
    static std::string format_key(const Key& src, Algorithm algorithm) {
        AES_KeyString str;
        aes_format_key(algorithm, &str, &src, ErrorDetailsThrowsInDestructor{});
        return reinterpret_cast<const char*>(&str);
    }

    void dump_key(const Key& src) const {
        if (verbose)
            std::cout << std::format("Key         : {}\n", format_key(src, get_algorithm()));
    }

    Block get_iv() const {
        return Block{impl.iv};
    }

    void dump_iv() const {
        if (verbose)
            std::cout << std::format("Init vector : {}\n", get_iv().to_string());
    }

    void dump_block(std::string_view header, const Block& block) const {
        if (verbose)
            std::cout << std::format("{}: {}\n", header, block.to_string());
    }

    void dump_plaintext(const Block& src) const {
        dump_block("Plaintext   ", src);
    }

    void dump_ciphertext(const Block& src) const {
        dump_block("Ciphertext  ", src);
    }

    AES_Box impl;
    bool verbose = false;
};

} // namespace aes

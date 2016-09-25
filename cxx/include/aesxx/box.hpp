// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "algorithm.hpp"
#include "error.hpp"
#include "mode.hpp"

#include <aes/all.h>

#include <cassert>
#include <cstddef>

#include <iostream>
#include <string>
#include <vector>

namespace aes
{
    class Box
    {
    public:
        typedef AES_BoxBlock Block;
        typedef AES_BoxKey Key;

        static std::string format_key(const Key& src, Algorithm algorithm)
        {
            AES_BoxKeyString str;
            aes_box_format_key(
                &str, algorithm, &src, ErrorDetailsThrowsInDestructor());
            return reinterpret_cast<const char*>(&str);
        }

        static std::string format_block(const Block& src, Algorithm algorithm)
        {
            AES_BoxBlockString str;
            aes_box_format_block(
                &str, algorithm, &src, ErrorDetailsThrowsInDestructor());
            return reinterpret_cast<const char*>(&str);
        }

        static void parse_block(
            Block& dest,
            Algorithm algorithm,
            const char* src)
        {
            aes_box_parse_block(&dest, algorithm, src,
                ErrorDetailsThrowsInDestructor());
        }

        static void parse_block(
            Block& dest,
            Algorithm algorithm,
            const std::string& src)
        {
            parse_block(dest, algorithm, src.c_str());
        }

        static void parse_key(
            Key& dest,
            Algorithm algorithm,
            const char* src)
        {
            aes_box_parse_key(&dest, algorithm, src,
                ErrorDetailsThrowsInDestructor());
        }

        static void parse_key(
            Key& dest,
            Algorithm algorithm,
            const std::string& src)
        {
            parse_key(dest, algorithm, src.c_str());
        }

        Box(Algorithm algorithm, const Key& key)
            : algorithm(algorithm)
            , mode(AES_ECB)
        {
            aes_box_init(&impl, algorithm, &key, mode, nullptr,
                ErrorDetailsThrowsInDestructor());
        }

        Box(Algorithm algorithm, const Key& key, Mode mode, const Block& iv)
            : algorithm(algorithm)
            , mode(mode)
        {
            aes_box_init(&impl, algorithm, &key, mode, &iv,
                ErrorDetailsThrowsInDestructor());
        }

        void encrypt_block(const Block& plaintext, Block& ciphertext)
        {
            aes_box_encrypt_block(
                &impl, &plaintext, &ciphertext,
                ErrorDetailsThrowsInDestructor());
        }

        void decrypt_block(const Block& ciphertext, Block& plaintext)
        {
            aes_box_decrypt_block(
                &impl, &ciphertext, &plaintext,
                ErrorDetailsThrowsInDestructor());
        }

        std::vector<unsigned char> encrypt_buffer(
            const void* src_buf,
            std::size_t src_size)
        {
            std::size_t dest_size;

            aes_box_encrypt_buffer(
                &impl,
                src_buf,
                src_size,
                nullptr,
                &dest_size,
                aes::ErrorDetailsThrowsInDestructor());

            std::vector<unsigned char> dest_buf;
            dest_buf.resize(dest_size);

            aes_box_encrypt_buffer(
                &impl,
                src_buf,
                src_size,
                dest_buf.data(),
                &dest_size,
                aes::ErrorDetailsThrowsInDestructor());

            dest_buf.resize(dest_size);
            return dest_buf;
        }

        std::vector<unsigned char> decrypt_buffer(
            const void* src_buf,
            std::size_t src_size)
        {
            std::size_t dest_size;

            aes_box_decrypt_buffer(
                &impl,
                src_buf,
                src_size,
                nullptr,
                &dest_size,
                aes::ErrorDetailsThrowsInDestructor());

            std::vector<unsigned char> dest_buf;
            dest_buf.resize(dest_size);

            aes_box_decrypt_buffer(
                &impl,
                src_buf,
                src_size,
                dest_buf.data(),
                &dest_size,
                aes::ErrorDetailsThrowsInDestructor());

            dest_buf.resize(dest_size);
            return dest_buf;
        }

        std::string format_block(const Block& src)
        {
            return format_block(src, get_algorithm());
        }

        std::string format_key(const Key& src)
        {
            return format_key(src, get_algorithm());
        }

        void parse_block(Block& dest, const char* src)
        {
            parse_block(dest, get_algorithm(), src);
        }

        void parse_block(Block& dest, const std::string& src)
        {
            parse_block(dest, src.c_str());
        }

        void parse_key(Key& dest, const char* src)
        {
            parse_key(dest, get_algorithm(), src);
        }

        void parse_key(Key& dest, const std::string& src)
        {
            parse_key(dest, src.c_str());
        }

        Algorithm get_algorithm() const { return algorithm; }

        Mode get_mode() const { return mode; }

    private:
        Key key;

        Algorithm algorithm;
        Mode mode;

        AES_Box impl;
    };
}

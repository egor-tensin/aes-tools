/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <aesnixx/all.hpp>

#include <cstdlib>

#include <iostream>

namespace
{
    template <typename BlockT>
    void dump_block(const char* name, const BlockT& block)
    {
        std::cout << name << ": " << block << "\n" << aesni::to_matrix_string(block) << "\n";
    }

    void dump_plaintext(const aesni::Block128& block)
    {
        dump_block("Plaintext", block);
    }

    template <typename BlockT>
    void dump_key(const BlockT& key)
    {
        dump_block("Key", key);
    }

    void dump_ciphertext(const aesni::Block128& ciphertext)
    {
        dump_block("Ciphertext", ciphertext);
    }

    void dump_iv(const aesni::Block128& iv)
    {
        dump_block("Initialization vector", iv);
    }

    void dump_next_iv(const aesni::Block128& next_iv)
    {
        dump_block("Next initialization vector", next_iv);
    }

    void dump_decrypted(const aesni::Block128& decrypted)
    {
        dump_block("Decrypted", decrypted);
    }

    void make_default_plaintext(aesni::Block128& plaintext)
    {
        aesni::make_block(plaintext, 0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
        dump_plaintext(plaintext);
    }

    void make_default_key(aesni::Block128& key)
    {
        aesni::make_block(key, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
        dump_key(key);
    }

    void make_default_key(aesni::Block192& key)
    {
        aesni::make_block(key, 0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
        dump_key(key);
    }

    void make_default_key(aesni::Block256& key)
    {
        aesni::make_block(key, 0x1f1e1d1c, 0x1b1a1918, 0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
        dump_key(key);
    }

    void make_default_iv(aesni::Block128& iv)
    {
        aesni::make_block(iv, 0xfedcba98, 0x76543210, 0xfedcba98, 0x76543210);
        dump_iv(iv);
    }

    template <typename KeyScheduleT>
    void dump_schedule(const char* name, const KeyScheduleT& schedule)
    {
        std::cout << name << ":\n";
        for (std::size_t i = 0; i < aesni::get_number_of_keys(schedule); ++i)
            std::cout << "\t[" << i << "]: " << schedule.keys[i] << "\n";
        std::cout << "\n";
    }

    template <typename KeyScheduleT>
    void dump_encryption_schedule(const KeyScheduleT& schedule)
    {
        dump_schedule("Encryption schedule", schedule);
    }

    template <typename KeyScheduleT>
    void dump_decryption_schedule(const KeyScheduleT& schedule)
    {
        dump_schedule("Decryption schedule", schedule);
    }
}

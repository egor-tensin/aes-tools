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
#include <type_traits>

namespace
{
    template <aesni::Algorithm algorithm>
    void dump_block(const char* name, const typename aesni::Types<algorithm>::Block& block)
    {
        std::cout << name << ": " << aesni::to_string<algorithm>(block) << "\n" << aesni::to_matrix_string<algorithm>(block) << "\n";
    }

    template <aesni::Algorithm algorithm>
    void dump_plaintext(const typename aesni::Types<algorithm>::Block& block)
    {
        dump_block<algorithm>("Plaintext", block);
    }

    template <aesni::Algorithm algorithm>
    void dump_key(const typename aesni::Types<algorithm>::Key& key)
    {
        std::cout << "Key: " << aesni::to_string<algorithm>(key) << "\n\n";
    }

    template <aesni::Algorithm algorithm>
    void dump_ciphertext(const typename aesni::Types<algorithm>::Block& ciphertext)
    {
        dump_block<algorithm>("Ciphertext", ciphertext);
    }

    template <aesni::Algorithm algorithm>
    void dump_iv(const typename aesni::Types<algorithm>::Block& iv)
    {
        dump_block<algorithm>("Initialization vector", iv);
    }

    template <aesni::Algorithm algorithm>
    void dump_round_keys(const char* name, const typename aesni::Types<algorithm>::RoundKeys& round_keys)
    {
        std::cout << name << ":\n";
        for (std::size_t i = 0; i < aesni::get_number_of_rounds<algorithm>(); ++i)
            std::cout << "\t[" << i << "]: " << aesni::to_string<algorithm>(round_keys.keys[i]) << "\n";
        std::cout << "\n";
    }

    template <aesni::Algorithm algorithm>
    void dump_encryption_keys(const typename aesni::Types<algorithm>::RoundKeys& round_keys)
    {
        dump_round_keys<algorithm>("Encryption round keys", round_keys);
    }

    template <aesni::Algorithm algorithm>
    void dump_decryption_keys(const typename aesni::Types<algorithm>::RoundKeys& round_keys)
    {
        dump_round_keys<algorithm>("Decryption round keys", round_keys);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode>
    void dump_wrapper(
        const aesni::EncryptWrapper<algorithm, mode>& wrapper)
    {
        dump_encryption_keys<algorithm>(wrapper.encryption_keys);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode>
    void dump_wrapper(
        const aesni::DecryptWrapper<algorithm, mode>& wrapper)
    {
        dump_decryption_keys<algorithm>(wrapper.decryption_keys);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode, typename std::enable_if<aesni::ModeRequiresInitializationVector<mode>::value>::type* = 0>
    void dump_next_iv(
        const aesni::EncryptWrapper<algorithm, mode>& wrapper)
    {
        dump_block<algorithm>("Next initialization vector", wrapper.iv);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode, typename std::enable_if<!aesni::ModeRequiresInitializationVector<mode>::value>::type* = 0>
    void dump_next_iv(
        const aesni::EncryptWrapper<algorithm, mode>&)
    { }

    template <aesni::Algorithm algorithm, aesni::Mode mode, typename std::enable_if<aesni::ModeRequiresInitializationVector<mode>::value>::type* = 0>
    void dump_next_iv(
        const aesni::DecryptWrapper<algorithm, mode>& wrapper)
    {
        dump_block<algorithm>("Next initialization vector", wrapper.iv);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode, typename std::enable_if<!aesni::ModeRequiresInitializationVector<mode>::value>::type* = 0>
    void dump_next_iv(
        const aesni::DecryptWrapper<algorithm, mode>&)
    { }
}

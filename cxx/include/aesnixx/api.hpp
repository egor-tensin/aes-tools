/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "algorithm.hpp"
#include "mode.hpp"

#include <cstddef>

#include <string>
#include <type_traits>

namespace aesni
{
    template <Algorithm algorithm>
    struct Types;

    template <Algorithm algorithm>
    std::size_t get_number_of_rounds();

    template <Algorithm algorithm>
    void from_string(
        typename Types<algorithm>::Block&,
        const char*);

    template <Algorithm algorithm>
    inline void from_string(
        typename Types<algorithm>::Block& dest,
        const std::string& src)
    {
        from_string<algorithm>(dest, src.c_str());
    }

    template <Algorithm algorithm>
    std::string to_string(const typename Types<algorithm>::Block&);

    template <Algorithm algorithm>
    std::string to_matrix_string(const typename Types<algorithm>::Block&);

    template <Algorithm algorithm>
    void from_string(
        typename Types<algorithm>::Key&,
        const char*);

    template <Algorithm algorithm>
    inline void from_string(
        typename Types<algorithm>::Key& dest,
        const std::string& src)
    {
        from_string<algorithm>(dest, src.c_str());
    }

    template <Algorithm algorithm>
    std::string to_string(const typename Types<algorithm>::Key&);

    template <Algorithm algorithm>
    inline void expand_key(
        const typename Types<algorithm>::Key& key,
        typename Types<algorithm>::RoundKeys& encryption_keys);

    template <Algorithm algorithm>
    inline void derive_decryption_keys(
        const typename Types<algorithm>::RoundKeys& encryption_keys,
        typename Types<algorithm>::RoundKeys& decryption_keys);

    template <Algorithm algorithm, Mode mode, typename std::enable_if<ModeRequiresInitializationVector<mode>::value>::type* = 0>
    inline void encrypt_block(
        const typename Types<algorithm>::Block& plaintext,
        const typename Types<algorithm>::RoundKeys& round_keys,
        typename Types<algorithm>::Block& iv,
        typename Types<algorithm>::Block& ciphertext);

    template <Algorithm algorithm, Mode mode, typename std::enable_if<!ModeRequiresInitializationVector<mode>::value>::type* = 0>
    inline void encrypt_block(
        const typename Types<algorithm>::Block& plaintext,
        const typename Types<algorithm>::RoundKeys& round_keys,
        typename Types<algorithm>::Block& ciphertext);

    template <Algorithm algorithm, Mode mode, typename std::enable_if<!ModeRequiresInitializationVector<mode>::value>::type* = 0>
    inline void encrypt_block(
        const typename Types<algorithm>::Block& plaintext,
        const typename Types<algorithm>::RoundKeys& round_keys,
        typename Types<algorithm>::Block&,
        typename Types<algorithm>::Block& ciphertext)
    {
        encrypt_block<algorithm, mode>(plaintext, round_keys, ciphertext);
    }

    template <Algorithm algorithm, Mode mode, typename std::enable_if<ModeRequiresInitializationVector<mode>::value>::type* = 0>
    inline void decrypt_block(
        const typename Types<algorithm>::Block& ciphertext,
        const typename Types<algorithm>::RoundKeys& round_keys,
        typename Types<algorithm>::Block& iv,
        typename Types<algorithm>::Block& plaintext);

    template <Algorithm algorithm, Mode mode, typename std::enable_if<!ModeRequiresInitializationVector<mode>::value>::type* = 0>
    inline void decrypt_block(
        const typename Types<algorithm>::Block& ciphertext,
        const typename Types<algorithm>::RoundKeys& round_keys,
        typename Types<algorithm>::Block& plaintext);

    template <Algorithm algorithm, Mode mode, typename std::enable_if<!ModeRequiresInitializationVector<mode>::value>::type* = 0>
    inline void decrypt_block(
        const typename Types<algorithm>::Block& ciphertext,
        const typename Types<algorithm>::RoundKeys& round_keys,
        typename Types<algorithm>::Block&,
        typename Types<algorithm>::Block& plaintext)
    {
        decrypt_block<algorithm, mode>(ciphertext, round_keys, plaintext);
    }

    template <Algorithm algorithm, Mode mode>
    struct EncryptWrapper
    {
        EncryptWrapper(
            const typename Types<algorithm>::Key& key,
            const typename Types<algorithm>::Block& iv) : iv(iv)
        {
            expand_key<algorithm>(key, encryption_keys);
        }

        inline void encrypt_block(
            const typename Types<algorithm>::Block& plaintext,
            typename Types<algorithm>::Block& ciphertext)
        {
            aesni::encrypt_block<algorithm, mode>(
                plaintext, encryption_keys, iv, ciphertext);
        }

        typename Types<algorithm>::Block iv;
        typename Types<algorithm>::RoundKeys encryption_keys;
    };

    template <Algorithm algorithm, Mode mode>
    struct DecryptWrapper
    {
        DecryptWrapper(
            const typename Types<algorithm>::Key& key,
            const typename Types<algorithm>::Block& iv) : iv(iv)
        {
            typename Types<algorithm>::RoundKeys encryption_keys;
            expand_key<algorithm>(key, encryption_keys);

            if (ModeUsesEncryptionKeysOnly<mode>::value)
            {
                decryption_keys = encryption_keys;
            }
            else
            {
                derive_decryption_keys<algorithm>(encryption_keys, decryption_keys);
            }
        }

        inline void decrypt_block(
            const typename Types<algorithm>::Block& ciphertext,
            typename Types<algorithm>::Block& plaintext)
        {
            aesni::decrypt_block<algorithm, mode>(
                ciphertext, decryption_keys, iv, plaintext);
        }

        typename Types<algorithm>::Block iv;
        typename Types<algorithm>::RoundKeys decryption_keys;
    };
}

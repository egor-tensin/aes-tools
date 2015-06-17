/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "common.hpp"

#include <aesni/all.h>

#include <aesnixx/all.hpp>

#include <exception>
#include <iostream>

int main()
{
    try
    {
        aesni::aes::Block plaintext;
        make_default_plaintext(plaintext);

        aesni::aes::Key128 key;
        make_default_key(key);

        aesni::aes::Block iv;
        make_default_iv(iv);

        aesni::aes::RoundKeys128 encryption_schedule;
        aesni_aes128_expand_key(&key, &encryption_schedule);
        dump_encryption_schedule(encryption_schedule);

        aesni::aes::Block next_iv;
        const auto ciphertext = aesni_aes128_encrypt_block_cbc(plaintext, &encryption_schedule, iv, &next_iv);
        dump_ciphertext(ciphertext);
        dump_next_iv(next_iv);

        aesni::aes::RoundKeys128 decryption_schedule;
        aesni_aes128_derive_decryption_keys(&encryption_schedule, &decryption_schedule);
        dump_decryption_schedule(decryption_schedule);

        aesni::aes::Block decrypted = aesni_aes128_decrypt_block_cbc(ciphertext, &decryption_schedule, iv, &next_iv);
        dump_decrypted(decrypted);
        dump_next_iv(next_iv);

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }
}

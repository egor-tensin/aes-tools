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

        aesni::aes::Key256 key;
        make_default_key(key);

        aesni::aes::Block iv;
        make_default_iv(iv);

        aesni::aes::RoundKeys256 encryption_schedule;
        aesni_aes256_expand_key(&key, &encryption_schedule);
        dump_encryption_schedule(encryption_schedule);

        aesni::aes::Block next_iv;
        const auto ciphertext = aesni_aes256_encrypt_block_ofb(plaintext, &encryption_schedule, iv, &next_iv);
        dump_ciphertext(ciphertext);
        dump_next_iv(next_iv);

        const auto decrypted = aesni_aes256_decrypt_block_ofb(ciphertext, &encryption_schedule, iv, &next_iv);
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

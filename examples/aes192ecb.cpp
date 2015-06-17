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

        aesni::aes::Key192 key;
        make_default_key(key);

        aesni::aes::RoundKeys192 encryption_schedule;
        aesni_aes192_expand_key(&key, &encryption_schedule);
        dump_encryption_schedule(encryption_schedule);

        const auto ciphertext = aesni_aes192_encrypt_block_ecb(plaintext, &encryption_schedule);
        dump_ciphertext(ciphertext);

        aesni::aes::RoundKeys192 decryption_schedule;
        aesni_aes192_derive_decryption_keys(&encryption_schedule, &decryption_schedule);
        dump_decryption_schedule(decryption_schedule);

        const auto decrypted = aesni_aes192_decrypt_block_ecb(ciphertext, &decryption_schedule);
        dump_decrypted(decrypted);

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }
}

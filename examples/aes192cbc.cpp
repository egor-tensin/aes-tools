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

        aesni::aes::Block iv;
        make_default_iv(iv);

        aesni::aes::RoundKeys192 encryption_keys;
        aesni_aes192_expand_key(&key, &encryption_keys);
        dump_encryption_keys(encryption_keys);

        aesni::aes::Block next_iv;
        const auto ciphertext = aesni_aes192_encrypt_block_cbc(plaintext, &encryption_keys, iv, &next_iv);
        dump_ciphertext(ciphertext);
        dump_next_iv(next_iv);

        aesni::aes::RoundKeys192 decryption_keys;
        aesni_aes192_derive_decryption_keys(&encryption_keys, &decryption_keys);
        dump_decryption_keys(decryption_keys);

        const auto decrypted = aesni_aes192_decrypt_block_cbc(ciphertext, &decryption_keys, iv, &next_iv);
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

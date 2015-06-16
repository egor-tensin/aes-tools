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
        aesni::Block128 plaintext;
        make_default_plaintext(plaintext);

        aesni::Block256 key;
        make_default_key(key);

        aesni::Block128 iv;
        make_default_iv(iv);

        aesni::KeySchedule256 encryption_schedule;
        aesni_expand_key_schedule256(&key, &encryption_schedule);
        dump_encryption_schedule(encryption_schedule);

        aesni::Block128 next_iv;
        const auto ciphertext = aesni_encrypt_block_cbc256(plaintext, &encryption_schedule, iv, &next_iv);
        dump_ciphertext(ciphertext);
        dump_next_iv(next_iv);

        aesni::KeySchedule256 decryption_schedule;
        aesni_invert_key_schedule256(&encryption_schedule, &decryption_schedule);
        dump_decryption_schedule(decryption_schedule);

        const auto decrypted = aesni_decrypt_block_cbc256(ciphertext, &decryption_schedule, iv, &next_iv);
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

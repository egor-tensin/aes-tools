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

        const auto ciphertext = aesni_encrypt_block_ctr256(plaintext, &encryption_schedule, iv, 0);
        dump_ciphertext(ciphertext);

        const auto decrypted = aesni_decrypt_block_ctr256(ciphertext, &encryption_schedule, iv, 0);
        dump_decrypted(decrypted);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}

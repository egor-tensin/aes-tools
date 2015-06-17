/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void exit_with_usage()
{
    puts("Usage: aes128cbc_decrypt_block.exe KEY0 IV0 [CIPHER0...] [-- KEY1 IV1 [CIPHER1...]...]");
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    for (--argc, ++argv; argc > -1; --argc, ++argv)
    {
        AesNI_Block128 plain, key, cipher, iv;
        AesNI_Aes128_RoundKeys key_schedule, inverted_schedule;

        if (argc < 2)
            exit_with_usage();

        if (aesni_is_error(aesni_parse_block128(&key, *argv, NULL)))
        {
            fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
            exit_with_usage();
        }

        if (aesni_is_error(aesni_parse_block128(&iv, argv[1], NULL)))
        {
            fprintf(stderr, "Invalid 128-bit AES block '%s'\n", argv[1]);
            exit_with_usage();
        }

        aesni_aes128_expand_key(key, &key_schedule);
        aesni_aes128_derive_decryption_keys(&key_schedule, &inverted_schedule);

        for (argc -= 2, argv += 2; argc > 0; --argc, ++argv)
        {
            if (strcmp("--", *argv) == 0)
                break;

            if (aesni_is_error(aesni_parse_block128(&cipher, *argv, NULL)))
            {
                fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
                continue;
            }
            plain = aesni_aes128_decrypt_block_cbc(cipher, &inverted_schedule, iv, &iv);
            aesni_print_block128(&plain, NULL);
        }
    }

    return 0;
}

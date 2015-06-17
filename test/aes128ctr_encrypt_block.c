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
    puts("Usage: aes128ctr_encrypt_block.exe KEY0 IV0 [PLAIN0...] [-- KEY1 IV1 [PLAIN1...]...]");
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    for (--argc, ++argv; argc > -1; --argc, ++argv)
    {
        AesNI_Block128 plaintext, ciphertext, iv;
        AesNI_Aes128_Key key;
        AesNI_Aes128_RoundKeys encryption_keys;

        if (argc < 2)
            exit_with_usage();

        if (aesni_is_error(aesni_aes128_parse_key(&key, *argv, NULL)))
        {
            fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
            exit_with_usage();
        }

        if (aesni_is_error(aesni_aes_parse_block(&iv, argv[1], NULL)))
        {
            fprintf(stderr, "Invalid 128-bit AES block '%s'\n", argv[1]);
            exit_with_usage();
        }

        aesni_aes128_expand_key(&key, &encryption_keys);

        int ctr = 0;

        for (argc -= 2, argv += 2; argc > 0; --argc, ++argv)
        {
            if (strcmp("--", *argv) == 0)
                break;

            if (aesni_is_error(aesni_aes_parse_block(&plaintext, *argv, NULL)))
            {
                fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
                continue;
            }
            ciphertext = aesni_aes128_encrypt_block_ctr(plaintext, &encryption_keys, iv, ctr++);
            aesni_aes_print_block(&ciphertext, NULL);
        }
    }

    return 0;
}

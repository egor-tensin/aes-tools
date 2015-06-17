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
    puts("Usage: aes192ecb_encrypt_block.exe KEY0 [PLAIN0...] [-- KEY1 [PLAIN1...]...]");
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    for (--argc, ++argv; argc > -1; --argc, ++argv)
    {
        AesNI_Block128 plaintext, ciphertext;
        AesNI_Block192 key;
        AesNI_Aes192_RoundKeys encryption_keys;

        if (argc < 1)
            exit_with_usage();

        if (aesni_is_error(aesni_parse_block192(&key, *argv, NULL)))
        {
            fprintf(stderr, "Invalid 192-bit AES block '%s'\n", *argv);
            exit_with_usage();
        }

        aesni_aes192_expand_key(&key, &encryption_keys);

        for (--argc, ++argv; argc > 0; --argc, ++argv)
        {
            if (strcmp("--", *argv) == 0)
                break;

            if (aesni_is_error(aesni_parse_block128(&plaintext, *argv, NULL)))
            {
                fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
                continue;
            }
            ciphertext = aesni_aes192_encrypt_block_ecb(plaintext, &encryption_keys);
            aesni_print_block128(&ciphertext, NULL);
        }
    }

    return 0;
}

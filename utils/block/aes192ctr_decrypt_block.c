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
    puts("Usage: aes192ctr_decrypt_block.exe KEY0 IV0 [CIPHERTEXT0...] [-- KEY1 IV1 [CIPHERTEXT1...]...]");
    exit(EXIT_FAILURE);
}

static void print_error(AesNI_StatusCode status)
{
    fprintf(stderr, "AesNI error: %s\n", aesni_strerror(status));
}

int main(int argc, char** argv)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    for (--argc, ++argv; argc > -1; --argc, ++argv)
    {
        AesNI_Block128 plaintext, ciphertext, iv;
        AesNI_Aes192_Key key;
        AesNI_Aes192_RoundKeys encryption_keys;

        if (argc < 2)
            exit_with_usage();

        if (aesni_is_error(status = aesni_aes192_parse_key(&key, *argv, NULL)))
        {
            print_error(status);
            exit_with_usage();
        }

        if (aesni_is_error(status = aesni_aes_parse_block(&iv, argv[1], NULL)))
        {
            print_error(status);
            exit_with_usage();
        }

        aesni_aes192_expand_key(&key, &encryption_keys);

        for (argc -= 2, argv += 2; argc > 0; --argc, ++argv)
        {
            if (strcmp("--", *argv) == 0)
                break;

            if (aesni_is_error(status = aesni_aes_parse_block(&ciphertext, *argv, NULL)))
            {
                print_error(status);
                continue;
            }

            plaintext = aesni_aes192_decrypt_block_ctr(ciphertext, &encryption_keys, iv, &iv);

            if (aesni_is_error(status = aesni_aes_print_block(&plaintext, NULL)))
            {
                print_error(status);
                continue;
            }
        }
    }

    return 0;
}
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
    puts("Usage: aes256ecb_decrypt_block.exe KEY0 [CIPHERTEXT0...] [-- KEY1 [CIPHERTEXT1...]...]");
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
        AesNI_Block128 plaintext, ciphertext;
        AesNI_Aes256_Key key;
        AesNI_Aes256_RoundKeys encryption_keys, decryption_keys;

        if (argc < 1)
            exit_with_usage();

        if (aesni_is_error(status = aesni_aes256_parse_key(&key, *argv, NULL)))
        {
            print_error(status);
            exit_with_usage();
        }

        aesni_aes256_expand_key(&key, &encryption_keys);
        aesni_aes256_derive_decryption_keys(&encryption_keys, &decryption_keys);

        for (--argc, ++argv; argc > 0; --argc, ++argv)
        {
            if (strcmp("--", *argv) == 0)
                break;

            if (aesni_is_error(status = aesni_aes_parse_block(&ciphertext, *argv, NULL)))
            {
                print_error(status);
                continue;
            }

            plaintext = aesni_aes256_decrypt_block_ecb(ciphertext, &decryption_keys);

            if (aesni_is_error(status = aesni_aes_print_block(&plaintext, NULL)))
            {
                print_error(status);
                continue;
            }
        }
    }

    return 0;
}

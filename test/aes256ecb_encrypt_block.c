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
    puts("Usage: aes256ecb_encrypt_block.exe KEY0 [PLAIN0...] [-- KEY1 [PLAIN1...]...]");
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    for (--argc, ++argv; argc > -1; --argc, ++argv)
    {
        AesNI_Block128 plain, cipher;
        AesNI_Block256 key;
        AesNI_KeySchedule256 key_schedule;

        if (argc < 1)
            exit_with_usage();

        if (aesni_is_error(aesni_parse_block256(&key, *argv, NULL)))
        {
            fprintf(stderr, "Invalid 256-bit AES block '%s'\n", *argv);
            exit_with_usage();
        }

        aesni_expand_key_schedule256(&key, &key_schedule);

        for (--argc, ++argv; argc > 0; --argc, ++argv)
        {
            if (strcmp("--", *argv) == 0)
                break;

            if (aesni_is_error(aesni_parse_block128(&plain, *argv, NULL)))
            {
                fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
                continue;
            }
            cipher = aesni_encrypt_block_ecb256(plain, &key_schedule);
            aesni_print_block128(&cipher, NULL);
        }
    }

    return 0;
}

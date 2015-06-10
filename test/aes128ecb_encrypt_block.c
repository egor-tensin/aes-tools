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
    puts("Usage: aes128ecb_encrypt_block.exe KEY0 [PLAIN0...] [-- KEY1 [PLAIN1...]...]");
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    for (--argc, ++argv; argc > -1; --argc, ++argv)
    {
        AesBlock128 plain, key, cipher;
        Aes128KeySchedule key_schedule;

        if (argc < 1)
            exit_with_usage();

        if (parse_aes_block128(&key, *argv) != 0)
        {
            fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
            exit_with_usage();
        }

        aes128_expand_key_schedule(key, &key_schedule);

        for (--argc, ++argv; argc > 0; --argc, ++argv)
        {
            if (strcmp("--", *argv) == 0)
                break;

            if (parse_aes_block128(&plain, *argv) != 0)
            {
                fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
                continue;
            }
            cipher = aes128ecb_encrypt_block(plain, &key_schedule);
            print_aes_block128(&cipher);
        }
    }

    return 0;
}

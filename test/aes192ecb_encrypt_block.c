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
    puts("Usage: aesni_encrypt_block_ecb192.exe KEY0 [PLAIN0...] [-- KEY1 [PLAIN1...]...]");
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    for (--argc, ++argv; argc > -1; --argc, ++argv)
    {
        AesNI_Block128 plain, cipher;
        AesNI_Block192 key;
        AesNI_KeySchedule192 key_schedule;

        if (argc < 1)
            exit_with_usage();

        if (aesni_parse_block192(&key, *argv) != 0)
        {
            fprintf(stderr, "Invalid 192-bit AES block '%s'\n", *argv);
            exit_with_usage();
        }

        aesni_expand_key_schedule192(&key, &key_schedule);

        for (--argc, ++argv; argc > 0; --argc, ++argv)
        {
            if (strcmp("--", *argv) == 0)
                break;

            if (aesni_parse_block128(&plain, *argv) != 0)
            {
                fprintf(stderr, "Invalid 128-bit AES block '%s'\n", *argv);
                continue;
            }
            cipher = aesni_encrypt_block_ecb192(plain, &key_schedule);
            aesni_print_block128(&cipher);
        }
    }

    return 0;
}

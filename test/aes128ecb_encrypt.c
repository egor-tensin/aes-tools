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

static void exit_with_usage(const char* argv0)
{
    printf("Usage: %s KEY [PLAIN...]\n", argv0);
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    __declspec(align(16)) AesBlock128 plain, key, cipher;
    __declspec(align(16)) Aes128KeySchedule key_schedule;

    if (argc < 2)
        exit_with_usage(argv[0]);

    if (parse_aes_block128(&key, argv[1]) != 0)
    {
        fprintf(stderr, "Invalid 128-bit AES block '%s'\n", argv[1]);
        exit_with_usage(argv[0]);
    }

    aes128_expand_key_schedule(key, &key_schedule);

    for (int i = 2; i < argc; ++i)
    {
        if (parse_aes_block128(&plain, argv[i]) != 0)
        {
            fprintf(stderr, "Invalid 128-bit AES block '%s'\n", argv[i]);
            continue;
        }
        cipher = aes128ecb_encrypt(plain, &key_schedule);
        print_aes_block128(&cipher);
    }

    return 0;
}

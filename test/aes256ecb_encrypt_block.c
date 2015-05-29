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
    __declspec(align(16)) AesBlock128 plain, cipher;
    __declspec(align(16)) AesBlock256 key;

    if (argc < 2)
        exit_with_usage(argv[0]);

    if (parse_aes_block256(&key, argv[1]) != 0)
    {
        fprintf(stderr, "Invalid 256-bit AES block '%s'\n", argv[1]);
        exit_with_usage(argv[0]);
    }

    for (int i = 2; i < argc; ++i)
    {
        if (parse_aes_block128(&plain, argv[i]) != 0)
        {
            fprintf(stderr, "Invalid 128-bit AES block '%s'\n", argv[i]);
            continue;
        }
        cipher = aes256ecb_encrypt(plain, &key);
        print_aes_block128(&cipher);
    }

    return 0;
}
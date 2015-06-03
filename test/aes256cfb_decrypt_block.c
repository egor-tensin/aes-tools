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
    printf("Usage: %s KEY INIT_VECTOR [CIPHER...]\n", argv0);
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    __declspec(align(16)) AesBlock128 plain, cipher, iv;
    __declspec(align(16)) AesBlock256 key;
    __declspec(align(16)) Aes256KeySchedule key_schedule;

    if (argc < 3)
        exit_with_usage(argv[0]);

    if (parse_aes_block256(&key, argv[1]) != 0)
    {
        fprintf(stderr, "Invalid 256-bit AES block '%s'\n", argv[1]);
        exit_with_usage(argv[0]);
    }

    if (parse_aes_block128(&iv, argv[2]) != 0)
    {
        fprintf(stderr, "Invalid 128-bit AES block '%s'\n", argv[2]);
        exit_with_usage(argv[0]);
    }

    aes256_expand_key_schedule(&key, &key_schedule);

    for (int i = 3; i < argc; ++i)
    {
        if (parse_aes_block128(&cipher, argv[i]) != 0)
        {
            fprintf(stderr, "Invalid 128-bit AES block '%s'\n", argv[i]);
            continue;
        }
        plain = aes256cfb_decrypt(cipher, &key_schedule, iv, &iv);
        print_aes_block128(&plain);
    }

    return 0;
}

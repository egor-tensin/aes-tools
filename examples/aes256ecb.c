/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <stdio.h>

int main()
{
    AesNI_Block128 plain, cipher, decrypted;
    AesNI_Block256 key;
    AesNI_KeySchedule256 key_schedule, inverted_schedule;

    plain = aesni_make_block128(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key = aesni_make_block256(0x1f1e1d1c, 0x1b1a1918, 0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &plain, NULL);
        printf("Plain: %s\n", str.str);
        aesni_print_block128_as_matrix(&plain, NULL);
    }

    printf("\n");

    {
        AesNI_BlockString256 str;
        aesni_format_block256(&str, &key, NULL);
        printf("Key: %s\n", str.str);
        aesni_print_block256_as_matrix(&key, NULL);
    }

    aesni_expand_key_schedule256(&key, &key_schedule);

    printf("\n");
    printf("Key schedule:\n");
    for (int i = 0; i < 15; ++i)
    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &key_schedule.keys[i], NULL);
        printf("\t[%d]: %s\n", i, str.str);
    }

    cipher = aesni_encrypt_block_ecb256(plain, &key_schedule);

    printf("\n");

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &cipher, NULL);
        printf("Cipher: %s\n", str.str);
        aesni_print_block128_as_matrix(&cipher, NULL);
    }

    aesni_invert_key_schedule256(&key_schedule, &inverted_schedule);

    printf("\n");
    printf("Inverted key schedule:\n");
    for (int i = 0; i < 15; ++i)
    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &inverted_schedule.keys[i], NULL);
        printf("\t[%d]: %s\n", i, str.str);
    }

    decrypted = aesni_decrypt_block_ecb256(cipher, &inverted_schedule);

    printf("\n");

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &decrypted, NULL);
        printf("Decrypted: %s\n", str.str);
        aesni_print_block128_as_matrix(&decrypted, NULL);
    }

    return 0;
}

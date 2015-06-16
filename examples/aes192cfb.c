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
    AesNI_Block128 plain, cipher, decrypted, iv, next_iv;
    AesNI_Block192 key;
    AesNI_KeySchedule192 key_schedule;

    plain = aesni_make_block128(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key = aesni_make_block192(0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
    iv = aesni_make_block128(0xfedcba98, 0x76543210, 0xfedcba98, 0x76543210);

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &plain, NULL);
        printf("Plain: %s\n", str.str);
        aesni_print_block128_as_matrix(&plain, NULL);
    }

    printf("\n");

    {
        AesNI_BlockString192 str;
        aesni_format_block192(&str, &key, NULL);
        printf("Key: %s\n", str.str);
        aesni_print_block192_as_matrix(&key, NULL);
    }

    printf("\n");

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &iv, NULL);
        printf("Initialization vector: %s\n", str.str);
        aesni_print_block128_as_matrix(&iv, NULL);
    }

    aesni_expand_key_schedule192(&key, &key_schedule);

    printf("\n");
    printf("Key schedule:\n");
    for (int i = 0; i < 13; ++i)
    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &key_schedule.keys[i], NULL);
        printf("\t[%d]: %s\n", i, str.str);
    }

    cipher = aesni_encrypt_block_cfb192(plain, &key_schedule, iv, &next_iv);

    printf("\n");

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &cipher, NULL);
        printf("Cipher: %s\n", str.str);
        aesni_print_block128_as_matrix(&cipher, NULL);
    }

    printf("\n");

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &next_iv, NULL);
        printf("Next initialization vector: %s\n", str.str);
        aesni_print_block128_as_matrix(&next_iv, NULL);
    }

    decrypted = aesni_decrypt_block_cfb192(cipher, &key_schedule, iv, &next_iv);

    printf("\n");

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &decrypted, NULL);
        printf("Decrypted: %s\n", str.str);
        aesni_print_block128_as_matrix(&decrypted, NULL);
    }

    printf("\n");

    {
        AesNI_BlockString128 str;
        aesni_format_block128(&str, &next_iv, NULL);
        printf("Next initialization vector: %s\n", str.str);
        aesni_print_block128_as_matrix(&next_iv, NULL);
    }

    return 0;
}

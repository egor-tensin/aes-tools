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
    __declspec(align(16)) AesBlock128 plain, key, cipher, decrypted, iv, next_iv;
    __declspec(align(16)) Aes128KeySchedule key_schedule, inverted_schedule;

    plain = make_aes_block128(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key = make_aes_block128(0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
    iv = make_aes_block128(0xfedcba98, 0x76543210, 0xfedcba98, 0x76543210);

    printf("Plain: %s\n", format_aes_block128(&plain).str);
    print_aes_block128_as_matrix(&plain);

    printf("\n");
    printf("Key: %s\n", format_aes_block128(&key).str);
    print_aes_block128_as_matrix(&key);

    printf("\n");
    printf("Initialization vector: %s\n", format_aes_block128(&iv).str);
    print_aes_block128_as_matrix(&iv);

    aes128_expand_key_schedule(key, &key_schedule);

    printf("\n");
    printf("Key schedule:\n");
    for (int i = 0; i < 11; ++i)
        printf("\t[%d]: %s\n", i, format_aes_block128(&key_schedule.keys[i]).str);

    cipher = aes128cbc_encrypt(plain, &key_schedule, iv, &next_iv);
    printf("\n");
    printf("Cipher: %s\n", format_aes_block128(&cipher).str);
    print_aes_block128_as_matrix(&cipher);

    printf("\n");
    printf("Next initialization vector: %s\n", format_aes_block128(&next_iv).str);
    print_aes_block128_as_matrix(&next_iv);

    aes128_invert_key_schedule(&key_schedule, &inverted_schedule);

    printf("\n");
    printf("Inverted key schedule:\n");
    for (int i = 0; i < 11; ++i)
        printf("\t[%d]: %s\n", i, format_aes_block128(&inverted_schedule.keys[i]).str);

    decrypted = aes128cbc_decrypt(cipher, &inverted_schedule, iv, &next_iv);
    printf("\n");
    printf("Decrypted: %s\n", format_aes_block128(&decrypted).str);
    print_aes_block128_as_matrix(&decrypted);

    printf("\n");
    printf("Next initialization vector: %s\n", format_aes_block128(&next_iv).str);
    print_aes_block128_as_matrix(&next_iv);

    return 0;
}

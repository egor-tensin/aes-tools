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
    __declspec(align(16)) AesBlock128 plain, cipher, decrypted, iv;
    __declspec(align(16)) AesBlock256 key;
    __declspec(align(16)) Aes256KeySchedule key_schedule;

    plain = make_aes_block128(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key = make_aes_block256(0x1f1e1d1c, 0x1b1a1918, 0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
    iv = make_aes_block128(0xfedcba98, 0x76543210, 0xfedcba98, 0x76543210);

    printf("Plain: %s\n", format_aes_block128(&plain).str);
    print_aes_block128_fips_matrix_style(&plain);

    printf("\n");
    printf("Key: %s\n", format_aes_block256(&key).str);
    print_aes_block256_fips_matrix_style(&key);

    printf("\n");
    printf("Initialization vector: %s\n", format_aes_block128(&iv).str);
    print_aes_block128_fips_matrix_style(&iv);

    aes256_expand_key_schedule(&key, &key_schedule);

    printf("\n");
    printf("Key schedule:\n");
    for (int i = 0; i < 15; ++i)
        printf("\t[%d]: %s\n", i, format_aes_block128(&key_schedule.keys[i]).str);

    cipher = aes256ctr_encrypt(plain, &key_schedule, iv, 0);
    printf("\n");
    printf("Cipher: %s\n", format_aes_block128(&cipher).str);
    print_aes_block128_fips_matrix_style(&cipher);

    decrypted = aes256ctr_decrypt(cipher, &key_schedule, iv, 0);
    printf("\n");
    printf("Decrypted: %s\n", format_aes_block128(&decrypted).str);
    print_aes_block128_fips_matrix_style(&decrypted);

    return 0;
}

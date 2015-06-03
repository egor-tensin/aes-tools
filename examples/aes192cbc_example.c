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
    __declspec(align(16)) AesBlock128 plain, cypher, decrypted, iv;
    __declspec(align(16)) AesBlock192 key;
    __declspec(align(16)) Aes192KeySchedule key_schedule, inverted_schedule;

    plain = make_aes_block128(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key = make_aes_block192(0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
    iv = make_aes_block128(0xfedcba98, 0x76543210, 0xfedcba98, 0x76543210);

    printf("Plain: %s\n", format_aes_block128(&plain).str);
    printf("       %s\n", format_aes_block128_fips_style(&plain).str);
    print_aes_block128_fips_matrix_style(&plain);

    printf("\n");
    printf("Key: %s\n", format_aes_block192(&key).str);
    printf("     %s\n", format_aes_block192_fips_style(&key).str);
    print_aes_block192_fips_matrix_style(&key);

    printf("\n");
    printf("Initialization vector: %s\n", format_aes_block128(&iv).str);
    printf("                       %s\n", format_aes_block128_fips_style(&iv).str);
    print_aes_block128_fips_matrix_style(&iv);

    aes192_expand_key_schedule(&key, &key_schedule);

    printf("\n");
    printf("Key schedule:\n");
    for (int i = 0; i < 13; ++i)
    {
        printf("\t[%d]: %s\n", i, format_aes_block128(&key_schedule.keys[i]).str);
        printf("\t[%d]: %s\n", i, format_aes_block128_fips_style(&key_schedule.keys[i]).str);
    }

    cypher = aes192cbc_encrypt(plain, &key_schedule, iv);
    printf("\n");
    printf("Cypher: %s\n", format_aes_block128(&cypher).str);
    printf("        %s\n", format_aes_block128_fips_style(&cypher).str);
    print_aes_block128_fips_matrix_style(&cypher);

    aes192_invert_key_schedule(&key_schedule, &inverted_schedule);

    printf("\n");
    printf("Inverted key schedule:\n");
    for (int i = 0; i < 13; ++i)
    {
        printf("\t[%d]: %s\n", i, format_aes_block128(&inverted_schedule.keys[i]).str);
        printf("\t[%d]: %s\n", i, format_aes_block128_fips_style(&inverted_schedule.keys[i]).str);
    }

    decrypted = aes192cbc_decrypt(cypher, &inverted_schedule, iv);
    printf("\n");
    printf("Decrypted: %s\n", format_aes_block128(&decrypted).str);
    printf("           %s\n", format_aes_block128_fips_style(&decrypted).str);
    print_aes_block128_fips_matrix_style(&decrypted);

    return 0;
}

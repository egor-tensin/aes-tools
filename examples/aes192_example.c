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
    __declspec(align(16)) AesBlock128 plain, cypher, decrypted;
    __declspec(align(16)) AesBlock192 key;

    plain = make_aes_block128(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key = make_aes_block192(0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);

    printf("Plain: %s\n", format_aes_block128(&plain).str);
    printf("       %s\n", format_aes_block128_fips_style(&plain).str);
    print_aes_block128_fips_matrix_style(&plain);

    printf("\n");
    printf("Key: %s\n", format_aes_block192(&key).str);
    printf("     %s\n", format_aes_block192_fips_style(&key).str);

    cypher = aes192ecb_encrypt(plain, &key);
    printf("\n");
    printf("Cypher: %s\n", format_aes_block128(&cypher).str);
    printf("        %s\n", format_aes_block128_fips_style(&cypher).str);
    print_aes_block128_fips_matrix_style(&cypher);

    decrypted = aes192ecb_decrypt(cypher, &key);
    printf("\n");
    printf("Decrypted: %s\n", format_aes_block128(&decrypted).str);
    printf("           %s\n", format_aes_block128_fips_style(&decrypted).str);
    print_aes_block128_fips_matrix_style(&decrypted);

    return 0;
}

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
    __declspec(align(16)) AesBlock plain, cypher, decrypted;
    __declspec(align(16)) AesBlock key_low, key_high, iv;

    plain    = make_aes_block(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key_low  = make_aes_block(0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
    key_high = make_aes_block(0x1f1e1d1c, 0x1b1a1918, 0x17161514, 0x13121110);
    iv       = make_aes_block(0xfedcba98, 0x76543210, 0xfedcba98, 0x76543210);

    printf("Plain:\n");
    print_aes_block(plain);

    printf("\nKey low:\n");
    print_aes_block(key_low);
    printf("\nKey high:\n");
    print_aes_block(key_high);

    printf("\nInitialization vector:\n");
    print_aes_block(iv);

    printf("\nCypher:\n");
    cypher = aes256cbc_encrypt(plain, key_low, key_high, &iv);
    print_aes_block(cypher);

    printf("\nDecrypted:\n");
    decrypted = aes256cbc_decrypt(cypher, key_low, key_high, &iv);
    print_aes_block(decrypted);

    return 0;
}

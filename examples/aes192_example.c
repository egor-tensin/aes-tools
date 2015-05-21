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
    __declspec(align(16)) AesBlock key_low, key_high;

    plain    = make_aes_block(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key_low  = make_aes_block(0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
    key_high = make_aes_block(         0,          0, 0x17161514, 0x13121110);

    printf("Plain:\n");
    print_aes_block(plain);

    printf("\nKey low:\n");
    print_aes_block(key_low);
    printf("\nKey high:\n");
    print_aes_block(key_high);

    printf("\nCypher:\n");
    cypher = aes192ecb_encrypt(plain, key_low, key_high);
    print_aes_block(cypher);

    printf("\nDecrypted:\n");
    decrypted = aes192ecb_decrypt(cypher, key_low, key_high);
    print_aes_block(decrypted);

    return 0;
}

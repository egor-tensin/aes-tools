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
    __declspec(align(16)) AesBlock plain, key, cypher, decrypted;

    plain = make_aes_block(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key   = make_aes_block(0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);

    printf("Plain:\n");
    print_aes_block(plain);

    printf("\nKey:\n");
    print_aes_block(key);

    printf("\nCypher:\n");
    cypher = aes128ecb_encrypt(plain, key);
    print_aes_block(cypher);

    printf("\nDecrypted:\n");
    decrypted = aes128ecb_decrypt(cypher, key);
    print_aes_block(decrypted);

    return 0;
}

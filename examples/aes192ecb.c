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
    AesNI_Block192 key;
    AesNI_KeySchedule192 key_schedule, inverted_schedule;

    plain = aesni_make_block128(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key = aesni_make_block192(0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);

    printf("Plain: %s\n", aesni_format_block128(&plain).str);
    aesni_print_block128_as_matrix(&plain);

    printf("\n");
    printf("Key: %s\n", aesni_format_block192(&key).str);
    aesni_print_block192_as_matrix(&key);

    aesni_expand_key_schedule192(&key, &key_schedule);

    printf("\n");
    printf("Key schedule:\n");
    for (int i = 0; i < 13; ++i)
        printf("\t[%d]: %s\n", i, aesni_format_block128(&key_schedule.keys[i]).str);

    cipher = aesni_encrypt_block_ecb192(plain, &key_schedule);
    printf("\n");
    printf("Cipher: %s\n", aesni_format_block128(&cipher).str);
    aesni_print_block128_as_matrix(&cipher);

    aesni_invert_key_schedule192(&key_schedule, &inverted_schedule);

    printf("\n");
    printf("Inverted key schedule:\n");
    for (int i = 0; i < 13; ++i)
        printf("\t[%d]: %s\n", i, aesni_format_block128(&inverted_schedule.keys[i]).str);

    decrypted = aesni_decrypt_block_ecb192(cipher, &inverted_schedule);
    printf("\n");
    printf("Decrypted: %s\n", aesni_format_block128(&decrypted).str);
    aesni_print_block128_as_matrix(&decrypted);

    return 0;
}

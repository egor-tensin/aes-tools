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
    AesNI_KeySchedule192 key_schedule, inverted_schedule;

    plain = aesni_make_block128(0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100);
    key = aesni_make_block192(0x17161514, 0x13121110, 0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
    iv = aesni_make_block128(0xfedcba98, 0x76543210, 0xfedcba98, 0x76543210);

    printf("Plain: %s\n", aesni_format_block128(&plain).str);
    aesni_print_block128_as_matrix(&plain);

    printf("\n");
    printf("Key: %s\n", aesni_format_block192(&key).str);
    aesni_print_block192_as_matrix(&key);

    printf("\n");
    printf("Initialization vector: %s\n", aesni_format_block128(&iv).str);
    aesni_print_block128_as_matrix(&iv);

    aesni_expand_key_schedule192(&key, &key_schedule);

    printf("\n");
    printf("Key schedule:\n");
    for (int i = 0; i < 13; ++i)
        printf("\t[%d]: %s\n", i, aesni_format_block128(&key_schedule.keys[i]).str);

    cipher = aesni_encrypt_block_cbc192(plain, &key_schedule, iv, &next_iv);
    printf("\n");
    printf("Cipher: %s\n", aesni_format_block128(&cipher).str);
    aesni_print_block128_as_matrix(&cipher);

    printf("\n");
    printf("Next initialization vector: %s\n", aesni_format_block128(&next_iv).str);
    aesni_print_block128_as_matrix(&next_iv);

    aesni_invert_key_schedule192(&key_schedule, &inverted_schedule);

    printf("\n");
    printf("Inverted key schedule:\n");
    for (int i = 0; i < 13; ++i)
        printf("\t[%d]: %s\n", i, aesni_format_block128(&inverted_schedule.keys[i]).str);

    decrypted = aesni_decrypt_block_cbc192(cipher, &inverted_schedule, iv, &next_iv);
    printf("\n");
    printf("Decrypted: %s\n", aesni_format_block128(&decrypted).str);
    aesni_print_block128_as_matrix(&decrypted);

    printf("\n");
    printf("Next initialization vector: %s\n", aesni_format_block128(&next_iv).str);
    aesni_print_block128_as_matrix(&next_iv);

    return 0;
}

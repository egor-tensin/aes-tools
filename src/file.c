/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <stdlib.h>
#include <string.h>

size_t aes128ecb_encrypt_file(const unsigned char* src,
                              size_t src_size,
                              unsigned char* dest,
                              Aes128KeySchedule* key_schedule)
{
    size_t rem_size = src_size % 16;
    size_t padding_size = 16 - rem_size;
    size_t dest_size = src_size + padding_size;

    if (dest == NULL)
        return dest_size;

    size_t src_len = src_size / 16;

    for (size_t i = 0; i < src_len; ++i, src += 16, dest += 16)
    {
        AesBlock128 plaintext = load_aes_block128(src);
        AesBlock128 ciphertext = aes128ecb_encrypt(plaintext, key_schedule);
        store_aes_block128(ciphertext, dest);
    }

    unsigned char padding[16] = { 0x10 };

    if (rem_size != 0)
    {
        memcpy(padding, src, rem_size);
        memset(padding + rem_size, padding_size, padding_size);
    }

    AesBlock128 plaintext = load_aes_block128(padding);
    AesBlock128 ciphertext = aes128ecb_encrypt(plaintext, key_schedule);
    store_aes_block128(ciphertext, dest);

    return dest_size;
}

size_t aes128ecb_decrypt_file(const unsigned char* src,
                              size_t src_size,
                              unsigned char* dest,
                              Aes128KeySchedule* inverted_schedule)
{
    size_t dest_size = src_size;

    if (dest == NULL)
        return dest_size;

    size_t src_len = src_size / 16;

    for (size_t i = 0; i < src_len - 1; ++i, src += 16, dest += 16)
    {
        AesBlock128 ciphertext = load_aes_block128(src);
        AesBlock128 plaintext = aes128ecb_decrypt(ciphertext, inverted_schedule);
        store_aes_block128(plaintext, dest);
    }

    AesBlock128 ciphertext = load_aes_block128(src);
    AesBlock128 plaintext = aes128ecb_decrypt(ciphertext, inverted_schedule);
    unsigned char padding[16];
    store_aes_block128(plaintext, padding);

    if (padding[0] == 0x10)
        return dest_size - 16;

    memcpy(dest, padding, 16 - padding[15]);
    return dest_size - padding[15];
}

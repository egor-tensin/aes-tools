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

static unsigned char FULL_BLOCK_PADDING[16] = { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };

size_t aes128ecb_encrypt_buffer(
    const unsigned char* src,
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
        AesBlock128 ciphertext = aes128ecb_encrypt_block(plaintext, key_schedule);
        store_aes_block128(ciphertext, dest);
    }

    unsigned char padding[16];

    if (rem_size == 0)
    {
        memcpy(padding, FULL_BLOCK_PADDING, 16);
    }
    else
    {
        memcpy(padding, src, rem_size);
        memset(padding + rem_size, padding_size, padding_size);
    }

    AesBlock128 plaintext = load_aes_block128(padding);
    AesBlock128 ciphertext = aes128ecb_encrypt_block(plaintext, key_schedule);
    store_aes_block128(ciphertext, dest);

    return dest_size;
}

static unsigned char get_padding_size(const unsigned char* padding)
{
    if (padding[15] < 0x01 || padding[15] > 0x10)
        return 0;

    for (int i = 16 - padding[15]; i < 15; ++i)
        if (padding[i] != padding[15])
            return 0;

    return padding[15];
}

size_t aes128ecb_decrypt_buffer(
    const unsigned char* src,
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
        AesBlock128 plaintext = aes128ecb_decrypt_block(ciphertext, inverted_schedule);
        store_aes_block128(plaintext, dest);
    }

    AesBlock128 ciphertext = load_aes_block128(src);
    AesBlock128 plaintext = aes128ecb_decrypt_block(ciphertext, inverted_schedule);
    unsigned char padding[16];
    store_aes_block128(plaintext, padding);

    unsigned char padding_size = get_padding_size(padding);

    if (padding_size == 0)
    {
        return dest_size - 16;
    }
    else
    {
        memcpy(dest, padding, 16 - padding_size);
        return dest_size - padding_size;
    }
}

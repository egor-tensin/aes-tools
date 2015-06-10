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

size_t aesni_encrypt_buffer_ecb128(
    const void* src,
    size_t src_size,
    void* dest,
    AesNI_KeySchedule128* key_schedule)
{
    size_t rem_size = src_size % 16;
    size_t padding_size = 16 - rem_size;
    size_t dest_size = src_size + padding_size;

    if (dest == NULL)
        return dest_size;

    size_t src_len = src_size / 16;

    for (size_t i = 0; i < src_len; ++i, (char*) src += 16, (char*) dest += 16)
    {
        AesNI_Block128 plaintext = aesni_load_block128(src);
        AesNI_Block128 ciphertext = aesni_encrypt_block_ecb128(plaintext, key_schedule);
        aesni_store_block128(dest, ciphertext);
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

    AesNI_Block128 plaintext = aesni_load_block128(padding);
    AesNI_Block128 ciphertext = aesni_encrypt_block_ecb128(plaintext, key_schedule);
    aesni_store_block128(dest, ciphertext);

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

size_t aesni_decrypt_buffer_ecb128(
    const void* src,
    size_t src_size,
    void* dest,
    AesNI_KeySchedule128* inverted_schedule)
{
    size_t dest_size = src_size;

    if (dest == NULL)
        return dest_size;

    size_t src_len = src_size / 16;

    for (size_t i = 0; i < src_len - 1; ++i, (char*) src += 16, (char*) dest += 16)
    {
        AesNI_Block128 ciphertext = aesni_load_block128(src);
        AesNI_Block128 plaintext = aesni_decrypt_block_ecb128(ciphertext, inverted_schedule);
        aesni_store_block128(dest, plaintext);
    }

    AesNI_Block128 ciphertext = aesni_load_block128(src);
    AesNI_Block128 plaintext = aesni_decrypt_block_ecb128(ciphertext, inverted_schedule);
    unsigned char padding[16];
    aesni_store_block128(padding, plaintext);

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

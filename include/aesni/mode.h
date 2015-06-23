/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <assert.h>

typedef enum
{
    AESNI_ECB,
    AESNI_CBC,
    AESNI_CFB,
    AESNI_OFB,
    AESNI_CTR,
}
AesNI_Mode;

#define AESNI_ENCRYPT_BLOCK_ECB(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_encrypt_block_ecb( \
    BlockT plaintext, \
    const KeyT* key) \
{ \
    assert(key); \
\
    return aesni_## prefix ##_encrypt_block_(plaintext, key); \
}

#define AESNI_DECRYPT_BLOCK_ECB(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_decrypt_block_ecb( \
    BlockT ciphertext, \
    const KeyT* key) \
{ \
    assert(key); \
\
    return aesni_## prefix ##_decrypt_block_(ciphertext, key); \
}

#define AESNI_ENCRYPT_BLOCK_CBC(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_encrypt_block_cbc( \
    BlockT plaintext, \
    const KeyT* key, \
    BlockT init_vector, \
    BlockT* next_init_vector) \
{ \
    assert(key); \
    assert(next_init_vector); \
\
    return *next_init_vector = aesni_## prefix ##_encrypt_block_ecb( \
        aesni_## prefix ##_xor_blocks(plaintext, init_vector), key); \
}

#define AESNI_DECRYPT_BLOCK_CBC(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_decrypt_block_cbc( \
    BlockT ciphertext, \
    const KeyT* key, \
    BlockT init_vector, \
    BlockT* next_init_vector) \
{ \
    assert(key); \
    assert(next_init_vector); \
\
    BlockT plaintext = aesni_## prefix ##_xor_blocks( \
        aesni_## prefix ##_decrypt_block_ecb(ciphertext, key), init_vector); \
    *next_init_vector = ciphertext; \
    return plaintext; \
}

#define AESNI_ENCRYPT_BLOCK_CFB(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_encrypt_block_cfb( \
    BlockT plaintext, \
    const KeyT* key, \
    BlockT init_vector, \
    BlockT* next_init_vector) \
{ \
    assert(key); \
    assert(next_init_vector); \
\
    return *next_init_vector = aesni_## prefix ##_xor_blocks( \
        aesni_## prefix ##_encrypt_block_ecb(init_vector, key), plaintext); \
}

#define AESNI_DECRYPT_BLOCK_CFB(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_decrypt_block_cfb( \
    BlockT ciphertext, \
    const KeyT* key, \
    BlockT init_vector, \
    BlockT* next_init_vector) \
{ \
    assert(key); \
    assert(next_init_vector); \
\
    BlockT plaintext = aesni_## prefix ##_xor_blocks( \
        aesni_## prefix ##_encrypt_block_ecb(init_vector, key), ciphertext); \
    *next_init_vector = ciphertext; \
    return plaintext; \
}

#define AESNI_ENCRYPT_BLOCK_OFB(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_encrypt_block_ofb( \
    BlockT plaintext, \
    const KeyT* key, \
    BlockT init_vector, \
    BlockT* next_init_vector) \
{ \
    assert(key); \
    assert(next_init_vector); \
\
    BlockT tmp = aesni_## prefix ##_encrypt_block_ecb(init_vector, key); \
    *next_init_vector = tmp; \
    return aesni_## prefix ##_xor_blocks(tmp, plaintext); \
}

#define AESNI_DECRYPT_BLOCK_OFB(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_decrypt_block_ofb( \
    BlockT ciphertext, \
    const KeyT* key, \
    BlockT init_vector, \
    BlockT* next_init_vector) \
{ \
    return aesni_## prefix ##_encrypt_block_ofb( \
        ciphertext, key, init_vector, next_init_vector); \
}

#define AESNI_ENCRYPT_BLOCK_CTR(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_encrypt_block_ctr( \
    BlockT plaintext, \
    const KeyT* key, \
    BlockT init_vector, \
    BlockT* next_init_vector) \
{ \
    assert(key); \
    assert(next_init_vector); \
\
    BlockT ciphertext = aesni_## prefix ##_xor_blocks( \
        plaintext, aesni_## prefix ##_encrypt_block_ecb(init_vector, key)); \
    *next_init_vector = aesni_## prefix ##_inc_block(init_vector); \
    return ciphertext; \
}

#define AESNI_DECRYPT_BLOCK_CTR(prefix, BlockT, KeyT) \
static __inline BlockT __fastcall aesni_## prefix ##_decrypt_block_ctr( \
    BlockT ciphertext, \
    const KeyT* key, \
    BlockT init_vector, \
    BlockT* next_init_vector) \
{ \
    return aesni_## prefix ##_encrypt_block_ctr( \
        ciphertext, key, init_vector, next_init_vector); \
}

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <assert.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    AES_ECB,
    AES_CBC,
    AES_CFB,
    AES_OFB,
    AES_CTR,
}
AES_Mode;

#define AES_ENCRYPT_BLOCK_ECB(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_encrypt_block_ECB( \
    AES_## prefix ##_Block plaintext, \
    const AES_## prefix ##_RoundKeys* encryption_keys) \
{ \
    assert(encryption_keys); \
\
    return aes_## prefix ##_encrypt_block_(plaintext, encryption_keys); \
}

#define AES_DECRYPT_BLOCK_ECB(prefix) \
static __inline AES_## prefix ##_Block  __fastcall aes_## prefix ##_decrypt_block_ECB( \
    AES_## prefix ##_Block ciphertext, \
    const AES_## prefix ##_RoundKeys* decryption_keys) \
{ \
    assert(decryption_keys); \
\
    return aes_## prefix ##_decrypt_block_(ciphertext, decryption_keys); \
}

#define AES_ENCRYPT_BLOCK_CBC(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_encrypt_block_CBC( \
    AES_## prefix ##_Block plaintext, \
    const AES_## prefix ##_RoundKeys* encryption_keys, \
    AES_## prefix ##_Block init_vector, \
    AES_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    return *next_init_vector = aes_## prefix ##_encrypt_block_( \
        aes_## prefix ##_xor_blocks(plaintext, init_vector), encryption_keys); \
}

#define AES_DECRYPT_BLOCK_CBC(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_decrypt_block_CBC( \
    AES_## prefix ##_Block ciphertext, \
    const AES_## prefix ##_RoundKeys* decryption_keys, \
    AES_## prefix ##_Block init_vector, \
    AES_## prefix ##_Block* next_init_vector) \
{ \
    assert(decryption_keys); \
    assert(next_init_vector); \
\
    AES_## prefix ##_Block plaintext = aes_## prefix ##_xor_blocks( \
        aes_## prefix ##_decrypt_block_(ciphertext, decryption_keys), init_vector); \
    *next_init_vector = ciphertext; \
    return plaintext; \
}

#define AES_ENCRYPT_BLOCK_CFB(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_encrypt_block_CFB( \
    AES_## prefix ##_Block plaintext, \
    const AES_## prefix ##_RoundKeys* encryption_keys, \
    AES_## prefix ##_Block init_vector, \
    AES_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    return *next_init_vector = aes_## prefix ##_xor_blocks( \
        aes_## prefix ##_encrypt_block_(init_vector, encryption_keys), plaintext); \
}

#define AES_DECRYPT_BLOCK_CFB(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_decrypt_block_CFB( \
    AES_## prefix ##_Block ciphertext, \
    const AES_## prefix ##_RoundKeys* encryption_keys, \
    AES_## prefix ##_Block init_vector, \
    AES_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    AES_## prefix ##_Block plaintext = aes_## prefix ##_xor_blocks( \
        aes_## prefix ##_encrypt_block_(init_vector, encryption_keys), ciphertext); \
    *next_init_vector = ciphertext; \
    return plaintext; \
}

#define AES_ENCRYPT_BLOCK_OFB(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_encrypt_block_OFB( \
    AES_## prefix ##_Block plaintext, \
    const AES_## prefix ##_RoundKeys* encryption_keys, \
    AES_## prefix ##_Block init_vector, \
    AES_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    AES_## prefix ##_Block tmp = aes_## prefix ##_encrypt_block_(init_vector, encryption_keys); \
    *next_init_vector = tmp; \
    return aes_## prefix ##_xor_blocks(tmp, plaintext); \
}

#define AES_DECRYPT_BLOCK_OFB(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_decrypt_block_OFB( \
    AES_## prefix ##_Block ciphertext, \
    const AES_## prefix ##_RoundKeys* encryption_keys, \
    AES_## prefix ##_Block init_vector, \
    AES_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    return aes_## prefix ##_encrypt_block_OFB( \
        ciphertext, encryption_keys, init_vector, next_init_vector); \
}

#define AES_ENCRYPT_BLOCK_CTR(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_encrypt_block_CTR( \
    AES_## prefix ##_Block plaintext, \
    const AES_## prefix ##_RoundKeys* encryption_keys, \
    AES_## prefix ##_Block init_vector, \
    AES_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    AES_## prefix ##_Block ciphertext = aes_## prefix ##_xor_blocks( \
        plaintext, aes_## prefix ##_encrypt_block_(init_vector, encryption_keys)); \
    *next_init_vector = aes_## prefix ##_inc_block(init_vector); \
    return ciphertext; \
}

#define AES_DECRYPT_BLOCK_CTR(prefix) \
static __inline AES_## prefix ##_Block __fastcall aes_## prefix ##_decrypt_block_CTR( \
    AES_## prefix ##_Block ciphertext, \
    const AES_## prefix ##_RoundKeys* encryption_keys, \
    AES_## prefix ##_Block init_vector, \
    AES_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    return aes_## prefix ##_encrypt_block_CTR( \
        ciphertext, encryption_keys, init_vector, next_init_vector); \
}

#ifdef __cplusplus
}
#endif

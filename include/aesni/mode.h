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
    AESNI_ECB,
    AESNI_CBC,
    AESNI_CFB,
    AESNI_OFB,
    AESNI_CTR,
}
AesNI_Mode;

#define AESNI_ENCRYPT_BLOCK_ECB(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_encrypt_block_ECB( \
    AesNI_## prefix ##_Block plaintext, \
    const AesNI_## prefix ##_RoundKeys* encryption_keys) \
{ \
    assert(encryption_keys); \
\
    return aesni_## prefix ##_encrypt_block_(plaintext, encryption_keys); \
}

#define AESNI_DECRYPT_BLOCK_ECB(prefix) \
static __inline AesNI_## prefix ##_Block  __fastcall aesni_## prefix ##_decrypt_block_ECB( \
    AesNI_## prefix ##_Block ciphertext, \
    const AesNI_## prefix ##_RoundKeys* decryption_keys) \
{ \
    assert(decryption_keys); \
\
    return aesni_## prefix ##_decrypt_block_(ciphertext, decryption_keys); \
}

#define AESNI_ENCRYPT_BLOCK_CBC(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_encrypt_block_CBC( \
    AesNI_## prefix ##_Block plaintext, \
    const AesNI_## prefix ##_RoundKeys* encryption_keys, \
    AesNI_## prefix ##_Block init_vector, \
    AesNI_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    return *next_init_vector = aesni_## prefix ##_encrypt_block_( \
        aesni_## prefix ##_xor_blocks(plaintext, init_vector), encryption_keys); \
}

#define AESNI_DECRYPT_BLOCK_CBC(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_decrypt_block_CBC( \
    AesNI_## prefix ##_Block ciphertext, \
    const AesNI_## prefix ##_RoundKeys* decryption_keys, \
    AesNI_## prefix ##_Block init_vector, \
    AesNI_## prefix ##_Block* next_init_vector) \
{ \
    assert(decryption_keys); \
    assert(next_init_vector); \
\
    AesNI_## prefix ##_Block plaintext = aesni_## prefix ##_xor_blocks( \
        aesni_## prefix ##_decrypt_block_(ciphertext, decryption_keys), init_vector); \
    *next_init_vector = ciphertext; \
    return plaintext; \
}

#define AESNI_ENCRYPT_BLOCK_CFB(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_encrypt_block_CFB( \
    AesNI_## prefix ##_Block plaintext, \
    const AesNI_## prefix ##_RoundKeys* encryption_keys, \
    AesNI_## prefix ##_Block init_vector, \
    AesNI_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    return *next_init_vector = aesni_## prefix ##_xor_blocks( \
        aesni_## prefix ##_encrypt_block_(init_vector, encryption_keys), plaintext); \
}

#define AESNI_DECRYPT_BLOCK_CFB(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_decrypt_block_CFB( \
    AesNI_## prefix ##_Block ciphertext, \
    const AesNI_## prefix ##_RoundKeys* encryption_keys, \
    AesNI_## prefix ##_Block init_vector, \
    AesNI_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    AesNI_## prefix ##_Block plaintext = aesni_## prefix ##_xor_blocks( \
        aesni_## prefix ##_encrypt_block_(init_vector, encryption_keys), ciphertext); \
    *next_init_vector = ciphertext; \
    return plaintext; \
}

#define AESNI_ENCRYPT_BLOCK_OFB(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_encrypt_block_OFB( \
    AesNI_## prefix ##_Block plaintext, \
    const AesNI_## prefix ##_RoundKeys* encryption_keys, \
    AesNI_## prefix ##_Block init_vector, \
    AesNI_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    AesNI_## prefix ##_Block tmp = aesni_## prefix ##_encrypt_block_(init_vector, encryption_keys); \
    *next_init_vector = tmp; \
    return aesni_## prefix ##_xor_blocks(tmp, plaintext); \
}

#define AESNI_DECRYPT_BLOCK_OFB(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_decrypt_block_OFB( \
    AesNI_## prefix ##_Block ciphertext, \
    const AesNI_## prefix ##_RoundKeys* encryption_keys, \
    AesNI_## prefix ##_Block init_vector, \
    AesNI_## prefix ##_Block* next_init_vector) \
{ \
    return aesni_## prefix ##_encrypt_block_OFB( \
        ciphertext, encryption_keys, init_vector, next_init_vector); \
}

#define AESNI_ENCRYPT_BLOCK_CTR(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_encrypt_block_CTR( \
    AesNI_## prefix ##_Block plaintext, \
    const AesNI_## prefix ##_RoundKeys* encryption_keys, \
    AesNI_## prefix ##_Block init_vector, \
    AesNI_## prefix ##_Block* next_init_vector) \
{ \
    assert(encryption_keys); \
    assert(next_init_vector); \
\
    AesNI_## prefix ##_Block ciphertext = aesni_## prefix ##_xor_blocks( \
        plaintext, aesni_## prefix ##_encrypt_block_(init_vector, encryption_keys)); \
    *next_init_vector = aesni_## prefix ##_inc_block(init_vector); \
    return ciphertext; \
}

#define AESNI_DECRYPT_BLOCK_CTR(prefix) \
static __inline AesNI_## prefix ##_Block __fastcall aesni_## prefix ##_decrypt_block_CTR( \
    AesNI_## prefix ##_Block ciphertext, \
    const AesNI_## prefix ##_RoundKeys* encryption_keys, \
    AesNI_## prefix ##_Block init_vector, \
    AesNI_## prefix ##_Block* next_init_vector) \
{ \
    return aesni_## prefix ##_encrypt_block_CTR( \
        ciphertext, encryption_keys, init_vector, next_init_vector); \
}

#ifdef __cplusplus
}
#endif

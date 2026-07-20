// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AES_ECB,
    AES_CBC,
    AES_CFB,
    AES_OFB,
    AES_CTR,
} AES_Mode;

#define AES_ENCRYPT_BLOCK_ECB(version)                                       \
    static inline AES_Block __fastcall aes##version##_encrypt_block_ECB(     \
        AES_Block plaintext, const AES##version##_RoundKeys* encryption_keys \
    ) {                                                                      \
        assert(encryption_keys);                                             \
                                                                             \
        return aes##version##_encrypt_block_(plaintext, encryption_keys);    \
    }

#define AES_DECRYPT_BLOCK_ECB(version)                                        \
    static inline AES_Block __fastcall aes##version##_decrypt_block_ECB(      \
        AES_Block ciphertext, const AES##version##_RoundKeys* decryption_keys \
    ) {                                                                       \
        assert(decryption_keys);                                              \
                                                                              \
        return aes##version##_decrypt_block_(ciphertext, decryption_keys);    \
    }

#define AES_ENCRYPT_BLOCK_CBC(version)                                     \
    static inline AES_Block __fastcall aes##version##_encrypt_block_CBC(   \
        AES_Block plaintext,                                               \
        const AES##version##_RoundKeys* encryption_keys,                   \
        AES_Block init_vector,                                             \
        AES_Block* next_init_vector                                        \
    ) {                                                                    \
        assert(encryption_keys);                                           \
        assert(next_init_vector);                                          \
                                                                           \
        return *next_init_vector = aes##version##_encrypt_block_(          \
                   aes_xor_blocks(plaintext, init_vector), encryption_keys \
               );                                                          \
    }

#define AES_DECRYPT_BLOCK_CBC(version)                                              \
    static inline AES_Block __fastcall aes##version##_decrypt_block_CBC(            \
        AES_Block ciphertext,                                                       \
        const AES##version##_RoundKeys* decryption_keys,                            \
        AES_Block init_vector,                                                      \
        AES_Block* next_init_vector                                                 \
    ) {                                                                             \
        assert(decryption_keys);                                                    \
        assert(next_init_vector);                                                   \
                                                                                    \
        AES_Block plaintext = aes_xor_blocks(                                       \
            aes##version##_decrypt_block_(ciphertext, decryption_keys), init_vector \
        );                                                                          \
        *next_init_vector = ciphertext;                                             \
        return plaintext;                                                           \
    }

#define AES_ENCRYPT_BLOCK_CFB(version)                                                    \
    static inline AES_Block __fastcall aes##version##_encrypt_block_CFB(                  \
        AES_Block plaintext,                                                              \
        const AES##version##_RoundKeys* encryption_keys,                                  \
        AES_Block init_vector,                                                            \
        AES_Block* next_init_vector                                                       \
    ) {                                                                                   \
        assert(encryption_keys);                                                          \
        assert(next_init_vector);                                                         \
                                                                                          \
        return *next_init_vector = aes_xor_blocks(                                        \
                   aes##version##_encrypt_block_(init_vector, encryption_keys), plaintext \
               );                                                                         \
    }

#define AES_DECRYPT_BLOCK_CFB(version)                                              \
    static inline AES_Block __fastcall aes##version##_decrypt_block_CFB(            \
        AES_Block ciphertext,                                                       \
        const AES##version##_RoundKeys* encryption_keys,                            \
        AES_Block init_vector,                                                      \
        AES_Block* next_init_vector                                                 \
    ) {                                                                             \
        assert(encryption_keys);                                                    \
        assert(next_init_vector);                                                   \
                                                                                    \
        AES_Block plaintext = aes_xor_blocks(                                       \
            aes##version##_encrypt_block_(init_vector, encryption_keys), ciphertext \
        );                                                                          \
        *next_init_vector = ciphertext;                                             \
        return plaintext;                                                           \
    }

#define AES_ENCRYPT_BLOCK_OFB(version)                                               \
    static inline AES_Block __fastcall aes##version##_encrypt_block_OFB(             \
        AES_Block plaintext,                                                         \
        const AES##version##_RoundKeys* encryption_keys,                             \
        AES_Block init_vector,                                                       \
        AES_Block* next_init_vector                                                  \
    ) {                                                                              \
        assert(encryption_keys);                                                     \
        assert(next_init_vector);                                                    \
                                                                                     \
        AES_Block tmp = aes##version##_encrypt_block_(init_vector, encryption_keys); \
        *next_init_vector = tmp;                                                     \
        return aes_xor_blocks(tmp, plaintext);                                       \
    }

#define AES_DECRYPT_BLOCK_OFB(version)                                   \
    static inline AES_Block __fastcall aes##version##_decrypt_block_OFB( \
        AES_Block ciphertext,                                            \
        const AES##version##_RoundKeys* encryption_keys,                 \
        AES_Block init_vector,                                           \
        AES_Block* next_init_vector                                      \
    ) {                                                                  \
        assert(encryption_keys);                                         \
        assert(next_init_vector);                                        \
                                                                         \
        return aes##version##_encrypt_block_OFB(                         \
            ciphertext, encryption_keys, init_vector, next_init_vector   \
        );                                                               \
    }

#define AES_ENCRYPT_BLOCK_CTR(version)                                             \
    static inline AES_Block __fastcall aes##version##_encrypt_block_CTR(           \
        AES_Block plaintext,                                                       \
        const AES##version##_RoundKeys* encryption_keys,                           \
        AES_Block init_vector,                                                     \
        AES_Block* next_init_vector                                                \
    ) {                                                                            \
        assert(encryption_keys);                                                   \
        assert(next_init_vector);                                                  \
                                                                                   \
        AES_Block ciphertext = aes_xor_blocks(                                     \
            plaintext, aes##version##_encrypt_block_(init_vector, encryption_keys) \
        );                                                                         \
        *next_init_vector = aes_inc_block(init_vector);                            \
        return ciphertext;                                                         \
    }

#define AES_DECRYPT_BLOCK_CTR(version)                                   \
    static inline AES_Block __fastcall aes##version##_decrypt_block_CTR( \
        AES_Block ciphertext,                                            \
        const AES##version##_RoundKeys* encryption_keys,                 \
        AES_Block init_vector,                                           \
        AES_Block* next_init_vector                                      \
    ) {                                                                  \
        assert(encryption_keys);                                         \
        assert(next_init_vector);                                        \
                                                                         \
        return aes##version##_encrypt_block_CTR(                         \
            ciphertext, encryption_keys, init_vector, next_init_vector   \
        );                                                               \
    }

#ifdef __cplusplus
}
#endif

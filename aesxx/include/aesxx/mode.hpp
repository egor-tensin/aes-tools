// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <aes/all.h>

#include <type_traits>

namespace aes {

typedef AES_Mode Mode;

inline constexpr bool mode_requires_init_vector(Mode mode) {
    return mode != AES_ECB;
}

inline constexpr bool mode_uses_encryption_keys_only(Mode mode) {
    return mode != AES_ECB && mode != AES_CBC;
}

#define AESXX_ENCRYPT_BLOCK_ECB(version)                                            \
    template <>                                                                     \
    inline void encrypt_block<AES_AES##version, AES_ECB>(                           \
        const typename Types<AES_AES##version>::Block& plaintext,                   \
        const typename Types<AES_AES##version>::RoundKeys& encryption_keys,         \
        typename Types<AES_AES##version>::Block&,                                   \
        typename Types<AES_AES##version>::Block& ciphertext                         \
    ) {                                                                             \
        ciphertext = aes##version##_encrypt_block_ECB(plaintext, &encryption_keys); \
    }

#define AESXX_DECRYPT_BLOCK_ECB(version)                                            \
    template <>                                                                     \
    inline void decrypt_block<AES_AES##version, AES_ECB>(                           \
        const typename Types<AES_AES##version>::Block& ciphertext,                  \
        const typename Types<AES_AES##version>::RoundKeys& decryption_keys,         \
        typename Types<AES_AES##version>::Block&,                                   \
        typename Types<AES_AES##version>::Block& plaintext                          \
    ) {                                                                             \
        plaintext = aes##version##_decrypt_block_ECB(ciphertext, &decryption_keys); \
    }

#define AESXX_ENCRYPT_BLOCK_CBC(version)                                                     \
    template <>                                                                              \
    inline void encrypt_block<AES_AES##version, AES_CBC>(                                    \
        const typename Types<AES_AES##version>::Block& plaintext,                            \
        const typename Types<AES_AES##version>::RoundKeys& encryption_keys,                  \
        typename Types<AES_AES##version>::Block& iv,                                         \
        typename Types<AES_AES##version>::Block& ciphertext                                  \
    ) {                                                                                      \
        ciphertext = aes##version##_encrypt_block_CBC(plaintext, &encryption_keys, iv, &iv); \
    }

#define AESXX_DECRYPT_BLOCK_CBC(version)                                                     \
    template <>                                                                              \
    inline void decrypt_block<AES_AES##version, AES_CBC>(                                    \
        const typename Types<AES_AES##version>::Block& ciphertext,                           \
        const typename Types<AES_AES##version>::RoundKeys& decryption_keys,                  \
        typename Types<AES_AES##version>::Block& iv,                                         \
        typename Types<AES_AES##version>::Block& plaintext                                   \
    ) {                                                                                      \
        plaintext = aes##version##_decrypt_block_CBC(ciphertext, &decryption_keys, iv, &iv); \
    }

#define AESXX_ENCRYPT_BLOCK_CFB(version)                                                     \
    template <>                                                                              \
    inline void encrypt_block<AES_AES##version, AES_CFB>(                                    \
        const typename Types<AES_AES##version>::Block& plaintext,                            \
        const typename Types<AES_AES##version>::RoundKeys& encryption_keys,                  \
        typename Types<AES_AES##version>::Block& iv,                                         \
        typename Types<AES_AES##version>::Block& ciphertext                                  \
    ) {                                                                                      \
        ciphertext = aes##version##_encrypt_block_CFB(plaintext, &encryption_keys, iv, &iv); \
    }

#define AESXX_DECRYPT_BLOCK_CFB(version)                                                     \
    template <>                                                                              \
    inline void decrypt_block<AES_AES##version, AES_CFB>(                                    \
        const typename Types<AES_AES##version>::Block& ciphertext,                           \
        const typename Types<AES_AES##version>::RoundKeys& encryption_keys,                  \
        typename Types<AES_AES##version>::Block& iv,                                         \
        typename Types<AES_AES##version>::Block& plaintext                                   \
    ) {                                                                                      \
        plaintext = aes##version##_decrypt_block_CFB(ciphertext, &encryption_keys, iv, &iv); \
    }

#define AESXX_ENCRYPT_BLOCK_OFB(version)                                                     \
    template <>                                                                              \
    inline void encrypt_block<AES_AES##version, AES_OFB>(                                    \
        const typename Types<AES_AES##version>::Block& plaintext,                            \
        const typename Types<AES_AES##version>::RoundKeys& encryption_keys,                  \
        typename Types<AES_AES##version>::Block& iv,                                         \
        typename Types<AES_AES##version>::Block& ciphertext                                  \
    ) {                                                                                      \
        ciphertext = aes##version##_encrypt_block_OFB(plaintext, &encryption_keys, iv, &iv); \
    }

#define AESXX_DECRYPT_BLOCK_OFB(version)                                                     \
    template <>                                                                              \
    inline void decrypt_block<AES_AES##version, AES_OFB>(                                    \
        const typename Types<AES_AES##version>::Block& ciphertext,                           \
        const typename Types<AES_AES##version>::RoundKeys& encryption_keys,                  \
        typename Types<AES_AES##version>::Block& iv,                                         \
        typename Types<AES_AES##version>::Block& plaintext                                   \
    ) {                                                                                      \
        plaintext = aes##version##_decrypt_block_OFB(ciphertext, &encryption_keys, iv, &iv); \
    }

#define AESXX_ENCRYPT_BLOCK_CTR(version)                                                     \
    template <>                                                                              \
    inline void encrypt_block<AES_AES##version, AES_CTR>(                                    \
        const typename Types<AES_AES##version>::Block& plaintext,                            \
        const typename Types<AES_AES##version>::RoundKeys& encryption_keys,                  \
        typename Types<AES_AES##version>::Block& iv,                                         \
        typename Types<AES_AES##version>::Block& ciphertext                                  \
    ) {                                                                                      \
        ciphertext = aes##version##_encrypt_block_CTR(plaintext, &encryption_keys, iv, &iv); \
    }

#define AESXX_DECRYPT_BLOCK_CTR(version)                                                     \
    template <>                                                                              \
    inline void decrypt_block<AES_AES##version, AES_CTR>(                                    \
        const typename Types<AES_AES##version>::Block& ciphertext,                           \
        const typename Types<AES_AES##version>::RoundKeys& encryption_keys,                  \
        typename Types<AES_AES##version>::Block& iv,                                         \
        typename Types<AES_AES##version>::Block& plaintext                                   \
    ) {                                                                                      \
        plaintext = aes##version##_decrypt_block_CTR(ciphertext, &encryption_keys, iv, &iv); \
    }

} // namespace aes

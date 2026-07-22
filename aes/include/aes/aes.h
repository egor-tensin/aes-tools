// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "block.h"
#include "round_keys.h"

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

AES_Block __fastcall aes128_encrypt_block_internal(AES_Block, const AES128_RoundKeys*);
AES_Block __fastcall aes192_encrypt_block_internal(AES_Block, const AES192_RoundKeys*);
AES_Block __fastcall aes256_encrypt_block_internal(AES_Block, const AES256_RoundKeys*);

AES_Block __fastcall aes128_decrypt_block_internal(AES_Block, const AES128_RoundKeys*);
AES_Block __fastcall aes192_decrypt_block_internal(AES_Block, const AES192_RoundKeys*);
AES_Block __fastcall aes256_decrypt_block_internal(AES_Block, const AES256_RoundKeys*);

static inline AES_Block aes128_encrypt_block(AES_Block plaintext, const AES128_RoundKeys* keys) {
    assert(keys);
    return aes128_encrypt_block_internal(plaintext, keys);
}

static inline AES_Block aes192_encrypt_block(AES_Block plaintext, const AES192_RoundKeys* keys) {
    assert(keys);
    return aes192_encrypt_block_internal(plaintext, keys);
}

static inline AES_Block aes256_encrypt_block(AES_Block plaintext, const AES256_RoundKeys* keys) {
    assert(keys);
    return aes256_encrypt_block_internal(plaintext, keys);
}

static inline AES_Block aes128_decrypt_block(AES_Block ciphertext, const AES128_RoundKeys* keys) {
    assert(keys);
    return aes128_decrypt_block_internal(ciphertext, keys);
}

static inline AES_Block aes192_decrypt_block(AES_Block ciphertext, const AES192_RoundKeys* keys) {
    assert(keys);
    return aes192_decrypt_block_internal(ciphertext, keys);
}

static inline AES_Block aes256_decrypt_block(AES_Block ciphertext, const AES256_RoundKeys* keys) {
    assert(keys);
    return aes256_decrypt_block_internal(ciphertext, keys);
}

#ifdef __cplusplus
}
#endif

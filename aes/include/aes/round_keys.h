/*
 * Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#pragma once

#include "block.h"
#include "error.h"
#include "key.h"

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    AES_Block keys[11];
} AES128_RoundKeys;

typedef struct {
    AES_Block keys[13];
} AES192_RoundKeys;

typedef struct {
    AES_Block keys[15];
} AES256_RoundKeys;

void __fastcall aes128_expand_key_internal(AES_Block key, AES128_RoundKeys* encryption_keys);

void __fastcall aes192_expand_key_internal(
    AES_Block key_lo,
    AES_Block key_hi,
    AES192_RoundKeys* encryption_keys
);

void __fastcall aes256_expand_key_internal(
    AES_Block key_lo,
    AES_Block key_hi,
    AES256_RoundKeys* encryption_keys
);

void __fastcall aes128_derive_decryption_keys_internal(
    const AES128_RoundKeys* encryption_keys,
    AES128_RoundKeys* decryption_keys
);

void __fastcall aes192_derive_decryption_keys_internal(
    const AES192_RoundKeys* encryption_keys,
    AES192_RoundKeys* decryption_keys
);

void __fastcall aes256_derive_decryption_keys_internal(
    const AES256_RoundKeys* encryption_keys,
    AES256_RoundKeys* decryption_keys
);

static inline void aes128_expand_key(const AES128_Key* key, AES128_RoundKeys* encryption_keys) {
    assert(encryption_keys);

    aes128_expand_key_internal(key->key, encryption_keys);
}

static inline void aes128_derive_decryption_keys(
    const AES128_RoundKeys* encryption_keys,
    AES128_RoundKeys* decryption_keys
) {
    assert(encryption_keys);
    assert(decryption_keys);

    aes128_derive_decryption_keys_internal(encryption_keys, decryption_keys);
}

static inline void aes192_expand_key(const AES192_Key* key, AES192_RoundKeys* encryption_keys) {
    assert(key);
    assert(encryption_keys);

    aes192_expand_key_internal(key->lo, key->hi, encryption_keys);
}

static inline void aes192_derive_decryption_keys(
    const AES192_RoundKeys* encryption_keys,
    AES192_RoundKeys* decryption_keys
) {
    assert(encryption_keys);
    assert(decryption_keys);

    aes192_derive_decryption_keys_internal(encryption_keys, decryption_keys);
}

static inline void aes256_expand_key(const AES256_Key* key, AES256_RoundKeys* encryption_keys) {
    assert(key);
    assert(encryption_keys);

    aes256_expand_key_internal(key->lo, key->hi, encryption_keys);
}

static inline void aes256_derive_decryption_keys(
    const AES256_RoundKeys* encryption_keys,
    AES256_RoundKeys* decryption_keys
) {
    assert(encryption_keys);
    assert(decryption_keys);

    aes256_derive_decryption_keys_internal(encryption_keys, decryption_keys);
}

#ifdef __cplusplus
}
#endif

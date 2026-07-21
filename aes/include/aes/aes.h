// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "data.h"
#include "error.h"
#include "mode.h"

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    AES_Block key;
} AES128_Key;

typedef struct {
    AES_Block hi;
    AES_Block lo;
} AES192_Key;

typedef struct {
    AES_Block hi;
    AES_Block lo;
} AES256_Key;

static inline AES128_Key aes128_make_key(int hi3, int hi2, int lo1, int lo0) {
    AES128_Key key;
    key.key = aes_make_block(hi3, hi2, lo1, lo0);
    return key;
}

static inline AES192_Key aes192_make_key(int hi5, int hi4, int lo3, int lo2, int lo1, int lo0) {
    AES192_Key key;
    key.hi = aes_make_block(0, 0, hi5, hi4);
    key.lo = aes_make_block(lo3, lo2, lo1, lo0);
    return key;
}

static inline AES256_Key aes256_make_key(
    int hi7,
    int hi6,
    int hi5,
    int hi4,
    int lo3,
    int lo2,
    int lo1,
    int lo0
) {
    AES256_Key key;
    key.hi = aes_make_block(hi7, hi6, hi5, hi4);
    key.lo = aes_make_block(lo3, lo2, lo1, lo0);
    return key;
}

typedef struct {
    char str[33];
} AES_BlockString;

typedef struct {
    char str[49];
} AES_BlockMatrixString;

AES_StatusCode aes_format_block(AES_BlockString*, const AES_Block*, AES_ErrorDetails*);

AES_StatusCode aes_format_block_as_matrix(
    AES_BlockMatrixString*,
    const AES_Block*,
    AES_ErrorDetails*
);

AES_StatusCode aes_print_block(const AES_Block*, AES_ErrorDetails*);

AES_StatusCode aes_print_block_as_matrix(const AES_Block*, AES_ErrorDetails*);

AES_StatusCode aes_parse_block(AES_Block* dest, const char* src, AES_ErrorDetails* err_details);

typedef struct {
    char str[33];
} AES128_KeyString;

typedef struct {
    char str[49];
} AES192_KeyString;

typedef struct {
    char str[65];
} AES256_KeyString;

AES_StatusCode aes128_format_key(AES128_KeyString*, const AES128_Key*, AES_ErrorDetails*);
AES_StatusCode aes192_format_key(AES192_KeyString*, const AES192_Key*, AES_ErrorDetails*);
AES_StatusCode aes256_format_key(AES256_KeyString*, const AES256_Key*, AES_ErrorDetails*);

AES_StatusCode aes128_print_key(const AES128_Key*, AES_ErrorDetails*);
AES_StatusCode aes192_print_key(const AES192_Key*, AES_ErrorDetails*);
AES_StatusCode aes256_print_key(const AES256_Key*, AES_ErrorDetails*);

AES_StatusCode aes128_parse_key(AES128_Key* dest, const char* src, AES_ErrorDetails* err_details);
AES_StatusCode aes192_parse_key(AES192_Key* dest, const char* src, AES_ErrorDetails* err_details);
AES_StatusCode aes256_parse_key(AES256_Key* dest, const char* src, AES_ErrorDetails* err_details);

typedef struct {
    AES_Block keys[11];
} AES128_RoundKeys;

typedef struct {
    AES_Block keys[13];
} AES192_RoundKeys;

typedef struct {
    AES_Block keys[15];
} AES256_RoundKeys;

void __fastcall aes128_expand_key_(AES_Block key, AES128_RoundKeys* encryption_keys);

void __fastcall aes192_expand_key_(
    AES_Block key_lo,
    AES_Block key_hi,
    AES192_RoundKeys* encryption_keys
);

void __fastcall aes256_expand_key_(
    AES_Block key_lo,
    AES_Block key_hi,
    AES256_RoundKeys* encryption_keys
);

void __fastcall aes128_derive_decryption_keys_(
    const AES128_RoundKeys* encryption_keys,
    AES128_RoundKeys* decryption_keys
);

void __fastcall aes192_derive_decryption_keys_(
    const AES192_RoundKeys* encryption_keys,
    AES192_RoundKeys* decryption_keys
);

void __fastcall aes256_derive_decryption_keys_(
    const AES256_RoundKeys* encryption_keys,
    AES256_RoundKeys* decryption_keys
);

AES_Block __fastcall aes128_encrypt_block_(AES_Block plaintext, const AES128_RoundKeys*);
AES_Block __fastcall aes192_encrypt_block_(AES_Block plaintext, const AES192_RoundKeys*);
AES_Block __fastcall aes256_encrypt_block_(AES_Block plaintext, const AES256_RoundKeys*);

AES_Block __fastcall aes128_decrypt_block_(AES_Block ciphertext, const AES128_RoundKeys*);
AES_Block __fastcall aes192_decrypt_block_(AES_Block ciphertext, const AES192_RoundKeys*);
AES_Block __fastcall aes256_decrypt_block_(AES_Block ciphertext, const AES256_RoundKeys*);

AES_ENCRYPT_BLOCK_ECB(128)
AES_DECRYPT_BLOCK_ECB(128)
AES_ENCRYPT_BLOCK_CBC(128)
AES_DECRYPT_BLOCK_CBC(128)
AES_ENCRYPT_BLOCK_CFB(128)
AES_DECRYPT_BLOCK_CFB(128)
AES_ENCRYPT_BLOCK_OFB(128)
AES_DECRYPT_BLOCK_OFB(128)
AES_ENCRYPT_BLOCK_CTR(128)
AES_DECRYPT_BLOCK_CTR(128)

AES_ENCRYPT_BLOCK_ECB(192)
AES_DECRYPT_BLOCK_ECB(192)
AES_ENCRYPT_BLOCK_CBC(192)
AES_DECRYPT_BLOCK_CBC(192)
AES_ENCRYPT_BLOCK_CFB(192)
AES_DECRYPT_BLOCK_CFB(192)
AES_ENCRYPT_BLOCK_OFB(192)
AES_DECRYPT_BLOCK_OFB(192)
AES_ENCRYPT_BLOCK_CTR(192)
AES_DECRYPT_BLOCK_CTR(192)

AES_ENCRYPT_BLOCK_ECB(256)
AES_DECRYPT_BLOCK_ECB(256)
AES_ENCRYPT_BLOCK_CBC(256)
AES_DECRYPT_BLOCK_CBC(256)
AES_ENCRYPT_BLOCK_CFB(256)
AES_DECRYPT_BLOCK_CFB(256)
AES_ENCRYPT_BLOCK_OFB(256)
AES_DECRYPT_BLOCK_OFB(256)
AES_ENCRYPT_BLOCK_CTR(256)
AES_DECRYPT_BLOCK_CTR(256)

static inline void __fastcall aes128_expand_key(
    const AES128_Key* key,
    AES128_RoundKeys* encryption_keys
) {
    assert(encryption_keys);

    aes128_expand_key_(key->key, encryption_keys);
}

static inline void __fastcall aes128_derive_decryption_keys(
    const AES128_RoundKeys* encryption_keys,
    AES128_RoundKeys* decryption_keys
) {
    assert(encryption_keys);
    assert(decryption_keys);

    aes128_derive_decryption_keys_(encryption_keys, decryption_keys);
}

static inline void __fastcall aes192_expand_key(
    const AES192_Key* key,
    AES192_RoundKeys* encryption_keys
) {
    assert(key);
    assert(encryption_keys);

    aes192_expand_key_(key->lo, key->hi, encryption_keys);
}

static inline void __fastcall aes192_derive_decryption_keys(
    const AES192_RoundKeys* encryption_keys,
    AES192_RoundKeys* decryption_keys
) {
    assert(encryption_keys);
    assert(decryption_keys);

    aes192_derive_decryption_keys_(encryption_keys, decryption_keys);
}

static inline void __fastcall aes256_expand_key(
    const AES256_Key* key,
    AES256_RoundKeys* encryption_keys
) {
    assert(key);
    assert(encryption_keys);

    aes256_expand_key_(key->lo, key->hi, encryption_keys);
}

static inline void __fastcall aes256_derive_decryption_keys(
    const AES256_RoundKeys* encryption_keys,
    AES256_RoundKeys* decryption_keys
) {
    assert(encryption_keys);
    assert(decryption_keys);

    aes256_derive_decryption_keys_(encryption_keys, decryption_keys);
}

#ifdef __cplusplus
}
#endif

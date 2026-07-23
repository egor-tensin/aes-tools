/*
 * Copyright (c) 2026 Egor Tensin <egor@tensin.name>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#pragma once

#include "block.h"
#include "error.h"

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

AES_StatusCode aes128_parse_key(AES128_Key* dest, const char* src, AES_ErrorDetails* err_details);
AES_StatusCode aes192_parse_key(AES192_Key* dest, const char* src, AES_ErrorDetails* err_details);
AES_StatusCode aes256_parse_key(AES256_Key* dest, const char* src, AES_ErrorDetails* err_details);

#ifdef __cplusplus
}
#endif

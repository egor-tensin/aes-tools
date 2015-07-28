/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "data.h"
#include "error.h"
#include "mode.h"

#include <assert.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef AesNI_Block128 AesNI_AES_Block;
typedef AesNI_AES_Block AesNI_AES128_Block;
typedef AesNI_AES_Block AesNI_AES192_Block;
typedef AesNI_AES_Block AesNI_AES256_Block;

typedef struct
{
    AesNI_AES_Block key;
}
AesNI_AES128_Key;

typedef struct
{
    AesNI_AES_Block hi;
    AesNI_AES_Block lo;
}
AesNI_AES192_Key;

typedef struct
{
    AesNI_AES_Block hi;
    AesNI_AES_Block lo;
}
AesNI_AES256_Key;

static __inline void aesni_AES_make_block(AesNI_AES_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    *dest = aesni_make_block128(hi3, hi2, lo1, lo0);
}

static __inline void aesni_AES128_make_block(AesNI_AES128_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    aesni_AES_make_block(dest, hi3, hi2, lo1, lo0);
}

static __inline void aesni_AES192_make_block(AesNI_AES192_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    aesni_AES_make_block(dest, hi3, hi2, lo1, lo0);
}

static __inline void aesni_AES256_make_block(AesNI_AES256_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    aesni_AES_make_block(dest, hi3, hi2, lo1, lo0);
}

static __inline void aesni_AES128_make_key(AesNI_AES128_Key* dest, int hi3, int hi2, int lo1, int lo0)
{
    aesni_AES_make_block(&dest->key, hi3, hi2, lo1, lo0);
}

static __inline void aesni_AES192_make_key(AesNI_AES192_Key* dest, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    aesni_AES_make_block(&dest->hi, 0, 0, hi5, hi4);
    aesni_AES_make_block(&dest->lo, lo3, lo2, lo1, lo0);
}

static __inline void aesni_AES256_make_key(AesNI_AES256_Key* dest, int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    aesni_AES_make_block(&dest->hi, hi7, hi6, hi5, hi4);
    aesni_AES_make_block(&dest->lo, lo3, lo2, lo1, lo0);
}

typedef struct { char str[33]; } AesNI_AES_BlockString;
typedef AesNI_AES_BlockString AesNI_AES128_BlockString;
typedef AesNI_AES_BlockString AesNI_AES192_BlockString;
typedef AesNI_AES_BlockString AesNI_AES256_BlockString;

typedef struct { char str[49]; } AesNI_AES_BlockMatrixString;
typedef AesNI_AES_BlockMatrixString AesNI_AES128_BlockMatrixString;
typedef AesNI_AES_BlockMatrixString AesNI_AES192_BlockMatrixString;
typedef AesNI_AES_BlockMatrixString AesNI_AES256_BlockMatrixString;

AesNI_StatusCode aesni_AES_format_block(
    AesNI_AES_BlockString*,
    const AesNI_AES_Block*,
    AesNI_ErrorDetails*);

static __inline AesNI_StatusCode aesni_AES128_format_block(
    AesNI_AES128_BlockString* dest,
    const AesNI_AES128_Block* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_format_block(dest, src, err_details);
}

static __inline AesNI_StatusCode aesni_AES192_format_block(
    AesNI_AES192_BlockString* dest,
    const AesNI_AES192_Block* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_format_block(dest, src, err_details);
}

static __inline AesNI_StatusCode aesni_AES256_format_block(
    AesNI_AES256_BlockString* dest,
    const AesNI_AES256_Block* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_format_block(dest, src, err_details);
}

AesNI_StatusCode aesni_AES_format_block_as_matrix(
    AesNI_AES_BlockMatrixString*,
    const AesNI_AES_Block*,
    AesNI_ErrorDetails*);

static __inline AesNI_StatusCode aesni_AES128_format_block_as_matrix(
    AesNI_AES128_BlockMatrixString* dest,
    const AesNI_AES128_Block* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_format_block_as_matrix(dest, src, err_details);
}

static __inline AesNI_StatusCode aesni_AES192_format_block_as_matrix(
    AesNI_AES192_BlockMatrixString* dest,
    const AesNI_AES192_Block* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_format_block_as_matrix(dest, src, err_details);
}

static __inline AesNI_StatusCode aesni_AES256_format_block_as_matrix(
    AesNI_AES256_BlockMatrixString* dest,
    const AesNI_AES256_Block* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_format_block_as_matrix(dest, src, err_details);
}

AesNI_StatusCode aesni_AES_print_block(
    const AesNI_AES_Block*,
    AesNI_ErrorDetails*);

static __inline AesNI_StatusCode aesni_AES128_print_block(
    const AesNI_AES128_Block* block,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_print_block(block, err_details);
}

static __inline AesNI_StatusCode aesni_AES192_print_block(
    const AesNI_AES192_Block* block,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_print_block(block, err_details);
}

static __inline AesNI_StatusCode aesni_AES256_print_block(
    const AesNI_AES256_Block* block,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_print_block(block, err_details);
}

AesNI_StatusCode aesni_AES_print_block_as_matrix(
    const AesNI_AES_Block*,
    AesNI_ErrorDetails*);

static __inline AesNI_StatusCode aesni_AES128_print_block_as_matrix(
    const AesNI_AES128_Block* block,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_print_block_as_matrix(block, err_details);
}

static __inline AesNI_StatusCode aesni_AES192_print_block_as_matrix(
    const AesNI_AES192_Block* block,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_print_block_as_matrix(block, err_details);
}

static __inline AesNI_StatusCode aesni_AES256_print_block_as_matrix(
    const AesNI_AES256_Block* block,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_print_block_as_matrix(block, err_details);
}

AesNI_StatusCode aesni_AES_parse_block(
    AesNI_AES_Block* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

static __inline AesNI_StatusCode aesni_AES128_parse_block(
    AesNI_AES128_Block* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_parse_block(dest, src, err_details);
}

static __inline AesNI_StatusCode aesni_AES192_parse_block(
    AesNI_AES192_Block* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_parse_block(dest, src, err_details);
}

static __inline AesNI_StatusCode aesni_AES256_parse_block(
    AesNI_AES256_Block* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    return aesni_AES_parse_block(dest, src, err_details);
}

typedef struct { char str[33]; } AesNI_AES128_KeyString;
typedef struct { char str[49]; } AesNI_AES192_KeyString;
typedef struct { char str[65]; } AesNI_AES256_KeyString;

AesNI_StatusCode aesni_AES128_format_key(
    AesNI_AES128_KeyString*,
    const AesNI_AES128_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_AES192_format_key(
    AesNI_AES192_KeyString*,
    const AesNI_AES192_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_AES256_format_key(
    AesNI_AES256_KeyString*,
    const AesNI_AES256_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_AES128_print_key(
    const AesNI_AES128_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_AES192_print_key(
    const AesNI_AES192_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_AES256_print_key(
    const AesNI_AES256_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_AES128_parse_key(
    AesNI_AES128_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_AES192_parse_key(
    AesNI_AES192_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_AES256_parse_key(
    AesNI_AES256_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

typedef struct
{
    AesNI_AES_Block keys[11];
}
AesNI_AES128_RoundKeys;

typedef struct
{
    AesNI_AES_Block keys[13];
}
AesNI_AES192_RoundKeys;

typedef struct
{
    AesNI_AES_Block keys[15];
}
AesNI_AES256_RoundKeys;

void __fastcall aesni_AES128_expand_key_(
    AesNI_AES_Block key,
    AesNI_AES128_RoundKeys* encryption_keys);

void __fastcall aesni_AES192_expand_key_(
    AesNI_AES_Block key_lo,
    AesNI_AES_Block key_hi,
    AesNI_AES192_RoundKeys* encryption_keys);

void __fastcall aesni_AES256_expand_key_(
    AesNI_AES_Block key_lo,
    AesNI_AES_Block key_hi,
    AesNI_AES256_RoundKeys* encryption_keys);

void __fastcall aesni_AES128_derive_decryption_keys_(
    const AesNI_AES128_RoundKeys* encryption_keys,
    AesNI_AES128_RoundKeys* decryption_keys);

void __fastcall aesni_AES192_derive_decryption_keys_(
    const AesNI_AES192_RoundKeys* encryption_keys,
    AesNI_AES192_RoundKeys* decryption_keys);

void __fastcall aesni_AES256_derive_decryption_keys_(
    const AesNI_AES256_RoundKeys* encryption_keys,
    AesNI_AES256_RoundKeys* decryption_keys);

AesNI_AES_Block __fastcall aesni_AES128_encrypt_block_(
    AesNI_AES_Block plaintext,
    const AesNI_AES128_RoundKeys*);

AesNI_AES_Block __fastcall aesni_AES192_encrypt_block_(
    AesNI_AES_Block plaintext,
    const AesNI_AES192_RoundKeys*);

AesNI_AES_Block __fastcall aesni_AES256_encrypt_block_(
    AesNI_AES_Block plaintext,
    const AesNI_AES256_RoundKeys*);

AesNI_AES_Block __fastcall aesni_AES128_decrypt_block_(
    AesNI_AES_Block ciphertext,
    const AesNI_AES128_RoundKeys*);

AesNI_AES_Block __fastcall aesni_AES192_decrypt_block_(
    AesNI_AES_Block ciphertext,
    const AesNI_AES192_RoundKeys*);

AesNI_AES_Block __fastcall aesni_AES256_decrypt_block_(
    AesNI_AES_Block ciphertext,
    const AesNI_AES256_RoundKeys*);

static __inline AesNI_AES_Block __fastcall aesni_AES_xor_blocks(
    AesNI_AES_Block a,
    AesNI_AES_Block b)
{
    return aesni_xor_block128(a, b);
}

static __inline AesNI_AES_Block __fastcall aesni_AES128_xor_blocks(
    AesNI_AES128_Block a,
    AesNI_AES128_Block b)
{
    return aesni_AES_xor_blocks(a, b);
}

static __inline AesNI_AES_Block __fastcall aesni_AES192_xor_blocks(
    AesNI_AES192_Block a,
    AesNI_AES192_Block b)
{
    return aesni_AES_xor_blocks(a, b);
}

static __inline AesNI_AES_Block __fastcall aesni_AES256_xor_blocks(
    AesNI_AES256_Block a,
    AesNI_AES256_Block b)
{
    return aesni_AES_xor_blocks(a, b);
}

static __inline AesNI_AES_Block __fastcall aesni_AES_inc_block(
    AesNI_AES_Block block)
{
    block = aesni_reverse_byte_order_block128(block);
    block = aesni_inc_block128(block);
    return aesni_reverse_byte_order_block128(block);
}

static __inline AesNI_AES_Block __fastcall aesni_AES128_inc_block(
    AesNI_AES128_Block block)
{
    return aesni_AES_inc_block(block);
}

static __inline AesNI_AES_Block __fastcall aesni_AES192_inc_block(
    AesNI_AES192_Block block)
{
    return aesni_AES_inc_block(block);
}

static __inline AesNI_AES_Block __fastcall aesni_AES256_inc_block(
    AesNI_AES256_Block block)
{
    return aesni_AES_inc_block(block);
}

AESNI_ENCRYPT_BLOCK_ECB(AES128);
AESNI_DECRYPT_BLOCK_ECB(AES128);
AESNI_ENCRYPT_BLOCK_CBC(AES128);
AESNI_DECRYPT_BLOCK_CBC(AES128);
AESNI_ENCRYPT_BLOCK_CFB(AES128);
AESNI_DECRYPT_BLOCK_CFB(AES128);
AESNI_ENCRYPT_BLOCK_OFB(AES128);
AESNI_DECRYPT_BLOCK_OFB(AES128);
AESNI_ENCRYPT_BLOCK_CTR(AES128);
AESNI_DECRYPT_BLOCK_CTR(AES128);

AESNI_ENCRYPT_BLOCK_ECB(AES192);
AESNI_DECRYPT_BLOCK_ECB(AES192);
AESNI_ENCRYPT_BLOCK_CBC(AES192);
AESNI_DECRYPT_BLOCK_CBC(AES192);
AESNI_ENCRYPT_BLOCK_CFB(AES192);
AESNI_DECRYPT_BLOCK_CFB(AES192);
AESNI_ENCRYPT_BLOCK_OFB(AES192);
AESNI_DECRYPT_BLOCK_OFB(AES192);
AESNI_ENCRYPT_BLOCK_CTR(AES192);
AESNI_DECRYPT_BLOCK_CTR(AES192);

AESNI_ENCRYPT_BLOCK_ECB(AES256);
AESNI_DECRYPT_BLOCK_ECB(AES256);
AESNI_ENCRYPT_BLOCK_CBC(AES256);
AESNI_DECRYPT_BLOCK_CBC(AES256);
AESNI_ENCRYPT_BLOCK_CFB(AES256);
AESNI_DECRYPT_BLOCK_CFB(AES256);
AESNI_ENCRYPT_BLOCK_OFB(AES256);
AESNI_DECRYPT_BLOCK_OFB(AES256);
AESNI_ENCRYPT_BLOCK_CTR(AES256);
AESNI_DECRYPT_BLOCK_CTR(AES256);

/**
 * \brief Expands an AES-128 key into 10 encryption round keys.
 *
 * \param[in] key The AES-128 key.
 * \param[out] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_AES128_expand_key(
    const AesNI_AES128_Key* key,
    AesNI_AES128_RoundKeys* encryption_keys)
{
    assert(encryption_keys);

    aesni_AES128_expand_key_(key->key, encryption_keys);
}

/**
 * \brief Derives AES-128 decryption round keys from AES-128 encryption round keys.
 *
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-128 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_AES128_derive_decryption_keys(
    const AesNI_AES128_RoundKeys* encryption_keys,
    AesNI_AES128_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aesni_AES128_derive_decryption_keys_(encryption_keys, decryption_keys);
}

/**
 * \brief Expands an AES-192 key into 12 encryption round keys.
 *
 * \param[in] key The AES-192 key.
 * \param[out] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_AES192_expand_key(
    const AesNI_AES192_Key* key,
    AesNI_AES192_RoundKeys* encryption_keys)
{
    assert(key);
    assert(encryption_keys);

    aesni_AES192_expand_key_(key->lo, key->hi, encryption_keys);
}

/**
 * \brief Derives AES-192 decryption round keys from AES-192 encryption round keys.
 *
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-192 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_AES192_derive_decryption_keys(
    const AesNI_AES192_RoundKeys* encryption_keys,
    AesNI_AES192_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aesni_AES192_derive_decryption_keys_(encryption_keys, decryption_keys);
}

/**
 * \brief Expands an AES-256 key into 14 encryption round keys.
 *
 * \param[in] key The AES-256 key.
 * \param[out] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_AES256_expand_key(
    const AesNI_AES256_Key* key,
    AesNI_AES256_RoundKeys* encryption_keys)
{
    assert(key);
    assert(encryption_keys);

    aesni_AES256_expand_key_(key->lo, key->hi, encryption_keys);
}

/**
 * \brief Derives AES-256 decryption round keys from AES-256 encryption round keys.
 *
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-256 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_AES256_derive_decryption_keys(
    const AesNI_AES256_RoundKeys* encryption_keys,
    AesNI_AES256_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aesni_AES256_derive_decryption_keys_(encryption_keys, decryption_keys);
}

#ifdef __cplusplus
}
#endif

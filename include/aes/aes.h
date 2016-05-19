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

typedef AES_Block128 AES_AES_Block;
typedef AES_AES_Block AES_AES128_Block;
typedef AES_AES_Block AES_AES192_Block;
typedef AES_AES_Block AES_AES256_Block;

typedef struct
{
    AES_AES_Block key;
}
AES_AES128_Key;

typedef struct
{
    AES_AES_Block hi;
    AES_AES_Block lo;
}
AES_AES192_Key;

typedef struct
{
    AES_AES_Block hi;
    AES_AES_Block lo;
}
AES_AES256_Key;

static __inline void aes_AES_make_block(AES_AES_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    *dest = aes_make_block128(hi3, hi2, lo1, lo0);
}

static __inline void aes_AES128_make_block(AES_AES128_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    aes_AES_make_block(dest, hi3, hi2, lo1, lo0);
}

static __inline void aes_AES192_make_block(AES_AES192_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    aes_AES_make_block(dest, hi3, hi2, lo1, lo0);
}

static __inline void aes_AES256_make_block(AES_AES256_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    aes_AES_make_block(dest, hi3, hi2, lo1, lo0);
}

static __inline void aes_AES128_make_key(AES_AES128_Key* dest, int hi3, int hi2, int lo1, int lo0)
{
    aes_AES_make_block(&dest->key, hi3, hi2, lo1, lo0);
}

static __inline void aes_AES192_make_key(AES_AES192_Key* dest, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    aes_AES_make_block(&dest->hi, 0, 0, hi5, hi4);
    aes_AES_make_block(&dest->lo, lo3, lo2, lo1, lo0);
}

static __inline void aes_AES256_make_key(AES_AES256_Key* dest, int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    aes_AES_make_block(&dest->hi, hi7, hi6, hi5, hi4);
    aes_AES_make_block(&dest->lo, lo3, lo2, lo1, lo0);
}

typedef struct { char str[33]; } AES_AES_BlockString;
typedef AES_AES_BlockString AES_AES128_BlockString;
typedef AES_AES_BlockString AES_AES192_BlockString;
typedef AES_AES_BlockString AES_AES256_BlockString;

typedef struct { char str[49]; } AES_AES_BlockMatrixString;
typedef AES_AES_BlockMatrixString AES_AES128_BlockMatrixString;
typedef AES_AES_BlockMatrixString AES_AES192_BlockMatrixString;
typedef AES_AES_BlockMatrixString AES_AES256_BlockMatrixString;

AES_StatusCode aes_AES_format_block(
    AES_AES_BlockString*,
    const AES_AES_Block*,
    AES_ErrorDetails*);

static __inline AES_StatusCode aes_AES128_format_block(
    AES_AES128_BlockString* dest,
    const AES_AES128_Block* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_format_block(dest, src, err_details);
}

static __inline AES_StatusCode aes_AES192_format_block(
    AES_AES192_BlockString* dest,
    const AES_AES192_Block* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_format_block(dest, src, err_details);
}

static __inline AES_StatusCode aes_AES256_format_block(
    AES_AES256_BlockString* dest,
    const AES_AES256_Block* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_format_block(dest, src, err_details);
}

AES_StatusCode aes_AES_format_block_as_matrix(
    AES_AES_BlockMatrixString*,
    const AES_AES_Block*,
    AES_ErrorDetails*);

static __inline AES_StatusCode aes_AES128_format_block_as_matrix(
    AES_AES128_BlockMatrixString* dest,
    const AES_AES128_Block* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_format_block_as_matrix(dest, src, err_details);
}

static __inline AES_StatusCode aes_AES192_format_block_as_matrix(
    AES_AES192_BlockMatrixString* dest,
    const AES_AES192_Block* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_format_block_as_matrix(dest, src, err_details);
}

static __inline AES_StatusCode aes_AES256_format_block_as_matrix(
    AES_AES256_BlockMatrixString* dest,
    const AES_AES256_Block* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_format_block_as_matrix(dest, src, err_details);
}

AES_StatusCode aes_AES_print_block(
    const AES_AES_Block*,
    AES_ErrorDetails*);

static __inline AES_StatusCode aes_AES128_print_block(
    const AES_AES128_Block* block,
    AES_ErrorDetails* err_details)
{
    return aes_AES_print_block(block, err_details);
}

static __inline AES_StatusCode aes_AES192_print_block(
    const AES_AES192_Block* block,
    AES_ErrorDetails* err_details)
{
    return aes_AES_print_block(block, err_details);
}

static __inline AES_StatusCode aes_AES256_print_block(
    const AES_AES256_Block* block,
    AES_ErrorDetails* err_details)
{
    return aes_AES_print_block(block, err_details);
}

AES_StatusCode aes_AES_print_block_as_matrix(
    const AES_AES_Block*,
    AES_ErrorDetails*);

static __inline AES_StatusCode aes_AES128_print_block_as_matrix(
    const AES_AES128_Block* block,
    AES_ErrorDetails* err_details)
{
    return aes_AES_print_block_as_matrix(block, err_details);
}

static __inline AES_StatusCode aes_AES192_print_block_as_matrix(
    const AES_AES192_Block* block,
    AES_ErrorDetails* err_details)
{
    return aes_AES_print_block_as_matrix(block, err_details);
}

static __inline AES_StatusCode aes_AES256_print_block_as_matrix(
    const AES_AES256_Block* block,
    AES_ErrorDetails* err_details)
{
    return aes_AES_print_block_as_matrix(block, err_details);
}

AES_StatusCode aes_AES_parse_block(
    AES_AES_Block* dest,
    const char* src,
    AES_ErrorDetails* err_details);

static __inline AES_StatusCode aes_AES128_parse_block(
    AES_AES128_Block* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_parse_block(dest, src, err_details);
}

static __inline AES_StatusCode aes_AES192_parse_block(
    AES_AES192_Block* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_parse_block(dest, src, err_details);
}

static __inline AES_StatusCode aes_AES256_parse_block(
    AES_AES256_Block* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    return aes_AES_parse_block(dest, src, err_details);
}

typedef struct { char str[33]; } AES_AES128_KeyString;
typedef struct { char str[49]; } AES_AES192_KeyString;
typedef struct { char str[65]; } AES_AES256_KeyString;

AES_StatusCode aes_AES128_format_key(
    AES_AES128_KeyString*,
    const AES_AES128_Key*,
    AES_ErrorDetails*);

AES_StatusCode aes_AES192_format_key(
    AES_AES192_KeyString*,
    const AES_AES192_Key*,
    AES_ErrorDetails*);

AES_StatusCode aes_AES256_format_key(
    AES_AES256_KeyString*,
    const AES_AES256_Key*,
    AES_ErrorDetails*);

AES_StatusCode aes_AES128_print_key(
    const AES_AES128_Key*,
    AES_ErrorDetails*);

AES_StatusCode aes_AES192_print_key(
    const AES_AES192_Key*,
    AES_ErrorDetails*);

AES_StatusCode aes_AES256_print_key(
    const AES_AES256_Key*,
    AES_ErrorDetails*);

AES_StatusCode aes_AES128_parse_key(
    AES_AES128_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_AES192_parse_key(
    AES_AES192_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details);

AES_StatusCode aes_AES256_parse_key(
    AES_AES256_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details);

typedef struct
{
    AES_AES_Block keys[11];
}
AES_AES128_RoundKeys;

typedef struct
{
    AES_AES_Block keys[13];
}
AES_AES192_RoundKeys;

typedef struct
{
    AES_AES_Block keys[15];
}
AES_AES256_RoundKeys;

void __fastcall aes_AES128_expand_key_(
    AES_AES_Block key,
    AES_AES128_RoundKeys* encryption_keys);

void __fastcall aes_AES192_expand_key_(
    AES_AES_Block key_lo,
    AES_AES_Block key_hi,
    AES_AES192_RoundKeys* encryption_keys);

void __fastcall aes_AES256_expand_key_(
    AES_AES_Block key_lo,
    AES_AES_Block key_hi,
    AES_AES256_RoundKeys* encryption_keys);

void __fastcall aes_AES128_derive_decryption_keys_(
    const AES_AES128_RoundKeys* encryption_keys,
    AES_AES128_RoundKeys* decryption_keys);

void __fastcall aes_AES192_derive_decryption_keys_(
    const AES_AES192_RoundKeys* encryption_keys,
    AES_AES192_RoundKeys* decryption_keys);

void __fastcall aes_AES256_derive_decryption_keys_(
    const AES_AES256_RoundKeys* encryption_keys,
    AES_AES256_RoundKeys* decryption_keys);

AES_AES_Block __fastcall aes_AES128_encrypt_block_(
    AES_AES_Block plaintext,
    const AES_AES128_RoundKeys*);

AES_AES_Block __fastcall aes_AES192_encrypt_block_(
    AES_AES_Block plaintext,
    const AES_AES192_RoundKeys*);

AES_AES_Block __fastcall aes_AES256_encrypt_block_(
    AES_AES_Block plaintext,
    const AES_AES256_RoundKeys*);

AES_AES_Block __fastcall aes_AES128_decrypt_block_(
    AES_AES_Block ciphertext,
    const AES_AES128_RoundKeys*);

AES_AES_Block __fastcall aes_AES192_decrypt_block_(
    AES_AES_Block ciphertext,
    const AES_AES192_RoundKeys*);

AES_AES_Block __fastcall aes_AES256_decrypt_block_(
    AES_AES_Block ciphertext,
    const AES_AES256_RoundKeys*);

static __inline AES_AES_Block __fastcall aes_AES_xor_blocks(
    AES_AES_Block a,
    AES_AES_Block b)
{
    return aes_xor_block128(a, b);
}

static __inline AES_AES_Block __fastcall aes_AES128_xor_blocks(
    AES_AES128_Block a,
    AES_AES128_Block b)
{
    return aes_AES_xor_blocks(a, b);
}

static __inline AES_AES_Block __fastcall aes_AES192_xor_blocks(
    AES_AES192_Block a,
    AES_AES192_Block b)
{
    return aes_AES_xor_blocks(a, b);
}

static __inline AES_AES_Block __fastcall aes_AES256_xor_blocks(
    AES_AES256_Block a,
    AES_AES256_Block b)
{
    return aes_AES_xor_blocks(a, b);
}

static __inline AES_AES_Block __fastcall aes_AES_inc_block(
    AES_AES_Block block)
{
    block = aes_reverse_byte_order_block128(block);
    block = aes_inc_block128(block);
    return aes_reverse_byte_order_block128(block);
}

static __inline AES_AES_Block __fastcall aes_AES128_inc_block(
    AES_AES128_Block block)
{
    return aes_AES_inc_block(block);
}

static __inline AES_AES_Block __fastcall aes_AES192_inc_block(
    AES_AES192_Block block)
{
    return aes_AES_inc_block(block);
}

static __inline AES_AES_Block __fastcall aes_AES256_inc_block(
    AES_AES256_Block block)
{
    return aes_AES_inc_block(block);
}

AES_ENCRYPT_BLOCK_ECB(AES128);
AES_DECRYPT_BLOCK_ECB(AES128);
AES_ENCRYPT_BLOCK_CBC(AES128);
AES_DECRYPT_BLOCK_CBC(AES128);
AES_ENCRYPT_BLOCK_CFB(AES128);
AES_DECRYPT_BLOCK_CFB(AES128);
AES_ENCRYPT_BLOCK_OFB(AES128);
AES_DECRYPT_BLOCK_OFB(AES128);
AES_ENCRYPT_BLOCK_CTR(AES128);
AES_DECRYPT_BLOCK_CTR(AES128);

AES_ENCRYPT_BLOCK_ECB(AES192);
AES_DECRYPT_BLOCK_ECB(AES192);
AES_ENCRYPT_BLOCK_CBC(AES192);
AES_DECRYPT_BLOCK_CBC(AES192);
AES_ENCRYPT_BLOCK_CFB(AES192);
AES_DECRYPT_BLOCK_CFB(AES192);
AES_ENCRYPT_BLOCK_OFB(AES192);
AES_DECRYPT_BLOCK_OFB(AES192);
AES_ENCRYPT_BLOCK_CTR(AES192);
AES_DECRYPT_BLOCK_CTR(AES192);

AES_ENCRYPT_BLOCK_ECB(AES256);
AES_DECRYPT_BLOCK_ECB(AES256);
AES_ENCRYPT_BLOCK_CBC(AES256);
AES_DECRYPT_BLOCK_CBC(AES256);
AES_ENCRYPT_BLOCK_CFB(AES256);
AES_DECRYPT_BLOCK_CFB(AES256);
AES_ENCRYPT_BLOCK_OFB(AES256);
AES_DECRYPT_BLOCK_OFB(AES256);
AES_ENCRYPT_BLOCK_CTR(AES256);
AES_DECRYPT_BLOCK_CTR(AES256);

/**
 * \brief Expands an AES-128 key into 10 encryption round keys.
 *
 * \param[in] key The AES-128 key.
 * \param[out] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aes_AES128_expand_key(
    const AES_AES128_Key* key,
    AES_AES128_RoundKeys* encryption_keys)
{
    assert(encryption_keys);

    aes_AES128_expand_key_(key->key, encryption_keys);
}

/**
 * \brief Derives AES-128 decryption round keys from AES-128 encryption round keys.
 *
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-128 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aes_AES128_derive_decryption_keys(
    const AES_AES128_RoundKeys* encryption_keys,
    AES_AES128_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aes_AES128_derive_decryption_keys_(encryption_keys, decryption_keys);
}

/**
 * \brief Expands an AES-192 key into 12 encryption round keys.
 *
 * \param[in] key The AES-192 key.
 * \param[out] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aes_AES192_expand_key(
    const AES_AES192_Key* key,
    AES_AES192_RoundKeys* encryption_keys)
{
    assert(key);
    assert(encryption_keys);

    aes_AES192_expand_key_(key->lo, key->hi, encryption_keys);
}

/**
 * \brief Derives AES-192 decryption round keys from AES-192 encryption round keys.
 *
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-192 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aes_AES192_derive_decryption_keys(
    const AES_AES192_RoundKeys* encryption_keys,
    AES_AES192_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aes_AES192_derive_decryption_keys_(encryption_keys, decryption_keys);
}

/**
 * \brief Expands an AES-256 key into 14 encryption round keys.
 *
 * \param[in] key The AES-256 key.
 * \param[out] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aes_AES256_expand_key(
    const AES_AES256_Key* key,
    AES_AES256_RoundKeys* encryption_keys)
{
    assert(key);
    assert(encryption_keys);

    aes_AES256_expand_key_(key->lo, key->hi, encryption_keys);
}

/**
 * \brief Derives AES-256 decryption round keys from AES-256 encryption round keys.
 *
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-256 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aes_AES256_derive_decryption_keys(
    const AES_AES256_RoundKeys* encryption_keys,
    AES_AES256_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aes_AES256_derive_decryption_keys_(encryption_keys, decryption_keys);
}

#ifdef __cplusplus
}
#endif

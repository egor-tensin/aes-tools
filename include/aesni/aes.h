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

#include <assert.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef AesNI_Block128 AesNI_Aes_Block;

typedef struct
{
    AesNI_Aes_Block key;
}
AesNI_Aes128_Key;

typedef struct
{
    AesNI_Aes_Block hi;
    AesNI_Aes_Block lo;
}
AesNI_Aes192_Key;

typedef struct
{
    AesNI_Aes_Block hi;
    AesNI_Aes_Block lo;
}
AesNI_Aes256_Key;

static __inline void aesni_aes_make_block(AesNI_Aes_Block* dest, int hi3, int hi2, int lo1, int lo0)
{
    *dest = aesni_make_block128(hi3, hi2, lo1, lo0);
}

static __inline void aesni_aes128_make_key(AesNI_Aes128_Key* dest, int hi3, int hi2, int lo1, int lo0)
{
    dest->key = aesni_make_block128(hi3, hi2, lo1, lo0);
}

static __inline void aesni_aes192_make_key(AesNI_Aes192_Key* dest, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    dest->hi = aesni_make_block128(0, 0, hi5, hi4);
    dest->lo = aesni_make_block128(lo3, lo2, lo1, lo0);
}

static __inline void aesni_aes256_make_key(AesNI_Aes256_Key* dest, int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
{
    dest->hi = aesni_make_block128(hi7, hi6, hi5, hi4);
    dest->lo = aesni_make_block128(lo3, lo2, lo1, lo0);
}

typedef struct { char str[33]; } AesNI_Aes_BlockString;
typedef struct { char str[49]; } AesNI_Aes_BlockMatrixString;

AesNI_StatusCode aesni_aes_format_block(
    AesNI_Aes_BlockString*,
    const AesNI_Aes_Block*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes_format_block_as_matrix(
    AesNI_Aes_BlockMatrixString*,
    const AesNI_Aes_Block*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes_print_block(
    const AesNI_Aes_Block*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes_print_block_as_matrix(
    const AesNI_Aes_Block*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes_parse_block(
    AesNI_Aes_Block* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

typedef AesNI_Aes_BlockString AesNI_Aes128_KeyString;
typedef struct { char str[49]; } AesNI_Aes192_KeyString;
typedef struct { char str[65]; } AesNI_Aes256_KeyString;

AesNI_StatusCode aesni_aes128_format_key(
    AesNI_Aes128_KeyString*,
    const AesNI_Aes128_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes192_format_key(
    AesNI_Aes192_KeyString*,
    const AesNI_Aes192_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes256_format_key(
    AesNI_Aes256_KeyString*,
    const AesNI_Aes256_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes128_print_key(
    const AesNI_Aes128_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes192_print_key(
    const AesNI_Aes192_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes256_print_key(
    const AesNI_Aes256_Key*,
    AesNI_ErrorDetails*);

AesNI_StatusCode aesni_aes128_parse_key(
    AesNI_Aes128_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_aes192_parse_key(
    AesNI_Aes192_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

AesNI_StatusCode aesni_aes256_parse_key(
    AesNI_Aes256_Key* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

typedef struct
{
    AesNI_Aes_Block keys[11];
}
AesNI_Aes128_RoundKeys;

typedef struct
{
    AesNI_Aes_Block keys[13];
}
AesNI_Aes192_RoundKeys;

typedef struct
{
    AesNI_Aes_Block keys[15];
}
AesNI_Aes256_RoundKeys;

void __fastcall aesni_aes128_expand_key_(
    AesNI_Aes_Block key,
    AesNI_Aes128_RoundKeys* encryption_keys);

void __fastcall aesni_aes192_expand_key_(
    AesNI_Aes_Block key_lo,
    AesNI_Aes_Block key_hi,
    AesNI_Aes192_RoundKeys* encryption_keys);

void __fastcall aesni_aes256_expand_key_(
    AesNI_Aes_Block key_lo,
    AesNI_Aes_Block key_hi,
    AesNI_Aes256_RoundKeys* encryption_keys);

void __fastcall aesni_aes128_derive_decryption_keys_(
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes128_RoundKeys* decryption_keys);

void __fastcall aesni_aes192_derive_decryption_keys_(
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes192_RoundKeys* decryption_keys);

void __fastcall aesni_aes256_derive_decryption_keys_(
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes256_RoundKeys* decryption_keys);

AesNI_Aes_Block __fastcall aesni_aes128_encrypt_block_(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes128_RoundKeys*);

AesNI_Aes_Block __fastcall aesni_aes192_encrypt_block_(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes192_RoundKeys*);

AesNI_Aes_Block __fastcall aesni_aes256_encrypt_block_(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes256_RoundKeys*);

AesNI_Aes_Block __fastcall aesni_aes128_decrypt_block_(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes128_RoundKeys*);

AesNI_Aes_Block __fastcall aesni_aes192_decrypt_block_(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes192_RoundKeys*);

AesNI_Aes_Block __fastcall aesni_aes256_decrypt_block_(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes256_RoundKeys*);

static __inline AesNI_Aes_Block __fastcall aesni_aes_inc_counter(AesNI_Aes_Block block)
{
    block = aesni_reverse_byte_order_block128(block);
    block = aesni_inc_block128(block);
    return aesni_reverse_byte_order_block128(block);
}

/**
 * \brief Expands an AES-128 key into 10 encryption round keys.
 *
 * \param[in] key The AES-128 key.
 * \param[out] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes128_expand_key(
    const AesNI_Aes128_Key* key,
    AesNI_Aes128_RoundKeys* encryption_keys)
{
    assert(encryption_keys);

    aesni_aes128_expand_key_(key->key, encryption_keys);
}

/**
 * \brief Derives AES-128 decryption round keys from AES-128 encryption round keys.
 *
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-128 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes128_derive_decryption_keys(
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes128_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aesni_aes128_derive_decryption_keys_(encryption_keys, decryption_keys);
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in ECB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_encrypt_block_ecb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys)
{
    assert(encryption_keys);

    return aesni_aes128_encrypt_block_(plaintext, encryption_keys);
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in ECB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] decryption_keys The AES-128 decryption round keys. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_decrypt_block_ecb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes128_RoundKeys* decryption_keys)
{
    assert(decryption_keys);

    return aesni_aes128_decrypt_block_(ciphertext, decryption_keys);
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in CBC mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_encrypt_block_cbc(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_aes128_encrypt_block_(aesni_xor_block128(plaintext, init_vector), encryption_keys);
    *next_init_vector = ciphertext;
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in CBC mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] decryption_keys The AES-128 decryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_decrypt_block_cbc(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes128_RoundKeys* decryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(decryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block plaintext = aesni_xor_block128(aesni_aes128_decrypt_block_(ciphertext, decryption_keys), init_vector);
    *next_init_vector = ciphertext;
    return plaintext;
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in CFB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_encrypt_block_cfb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_xor_block128(aesni_aes128_encrypt_block_(init_vector, encryption_keys), plaintext);
    *next_init_vector = ciphertext;
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in CFB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-128 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_decrypt_block_cfb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block plaintext = aesni_xor_block128(aesni_aes128_encrypt_block_(init_vector, encryption_keys), ciphertext);
    *next_init_vector = ciphertext;
    return plaintext;
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in OFB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_encrypt_block_ofb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block tmp = aesni_aes128_encrypt_block_(init_vector, encryption_keys);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, plaintext);
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in OFB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-128 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_decrypt_block_ofb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    return aesni_aes128_encrypt_block_ofb(ciphertext, encryption_keys, init_vector, next_init_vector);
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in CTR mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_encrypt_block_ctr(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_xor_block128(plaintext, aesni_aes128_encrypt_block_(init_vector, encryption_keys));
    *next_init_vector = aesni_aes_inc_counter(init_vector);
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in CTR mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-128 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes128_decrypt_block_ctr(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    return aesni_aes128_encrypt_block_ctr(ciphertext, encryption_keys, init_vector, next_init_vector);
}

/**
 * \brief Expands an AES-192 key into 12 encryption round keys.
 *
 * \param[in] key The AES-192 key.
 * \param[out] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes192_expand_key(
    const AesNI_Aes192_Key* key,
    AesNI_Aes192_RoundKeys* encryption_keys)
{
    assert(key);
    assert(encryption_keys);

    aesni_aes192_expand_key_(key->lo, key->hi, encryption_keys);
}

/**
 * \brief Derives AES-192 decryption round keys from AES-192 encryption round keys.
 *
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-192 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes192_derive_decryption_keys(
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes192_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aesni_aes192_derive_decryption_keys_(encryption_keys, decryption_keys);
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in ECB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_encrypt_block_ecb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys)
{
    assert(encryption_keys);

    return aesni_aes192_encrypt_block_(plaintext, encryption_keys);
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in ECB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] decryption_keys The AES-192 decryption round keys. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_decrypt_block_ecb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes192_RoundKeys* decryption_keys)
{
    assert(decryption_keys);

    return aesni_aes192_decrypt_block_(ciphertext, decryption_keys);
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in CBC mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_encrypt_block_cbc(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_aes192_encrypt_block_(aesni_xor_block128(plaintext, init_vector), encryption_keys);
    *next_init_vector = ciphertext;
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in CBC mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] decryption_keys The AES-192 decryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_decrypt_block_cbc(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes192_RoundKeys* decryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(decryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block plaintext = aesni_xor_block128(aesni_aes192_decrypt_block_(ciphertext, decryption_keys), init_vector);
    *next_init_vector = ciphertext;
    return plaintext;
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in CFB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_encrypt_block_cfb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_xor_block128(aesni_aes192_encrypt_block_(init_vector, encryption_keys), plaintext);
    *next_init_vector = ciphertext;
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in CFB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-192 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_decrypt_block_cfb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block plaintext = aesni_xor_block128(aesni_aes192_encrypt_block_(init_vector, encryption_keys), ciphertext);
    *next_init_vector = ciphertext;
    return plaintext;
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in OFB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_encrypt_block_ofb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block tmp = aesni_aes192_encrypt_block_(init_vector, encryption_keys);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, plaintext);
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in OFB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-192 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_decrypt_block_ofb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    return aesni_aes192_encrypt_block_ofb(ciphertext, encryption_keys, init_vector, next_init_vector);
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in CTR mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_encrypt_block_ctr(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_xor_block128(plaintext, aesni_aes192_encrypt_block_(init_vector, encryption_keys));
    *next_init_vector = aesni_aes_inc_counter(init_vector);
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in CTR mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-192 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes192_decrypt_block_ctr(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    return aesni_aes192_encrypt_block_ctr(ciphertext, encryption_keys, init_vector, next_init_vector);
}

/**
 * \brief Expands an AES-256 key into 14 encryption round keys.
 *
 * \param[in] key The AES-256 key.
 * \param[out] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes256_expand_key(
    const AesNI_Aes256_Key* key,
    AesNI_Aes256_RoundKeys* encryption_keys)
{
    assert(key);
    assert(encryption_keys);

    aesni_aes256_expand_key_(key->lo, key->hi, encryption_keys);
}

/**
 * \brief Derives AES-256 decryption round keys from AES-256 encryption round keys.
 *
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 * \param[out] decryption_keys The AES-256 decryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes256_derive_decryption_keys(
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes256_RoundKeys* decryption_keys)
{
    assert(encryption_keys);
    assert(decryption_keys);

    aesni_aes256_derive_decryption_keys_(encryption_keys, decryption_keys);
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in ECB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_encrypt_block_ecb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys)
{
    assert(encryption_keys);

    return aesni_aes256_encrypt_block_(plaintext, encryption_keys);
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in ECB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] decryption_keys The AES-256 decryption round keys. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_decrypt_block_ecb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes256_RoundKeys* decryption_keys)
{
    assert(decryption_keys);

    return aesni_aes256_decrypt_block_(ciphertext, decryption_keys);
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in CBC mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_encrypt_block_cbc(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_aes256_encrypt_block_(aesni_xor_block128(plaintext, init_vector), encryption_keys);
    *next_init_vector = ciphertext;
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in CBC mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] decryption_keys The AES-256 decryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_decrypt_block_cbc(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes256_RoundKeys* decryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(decryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block plaintext = aesni_xor_block128(aesni_aes256_decrypt_block_(ciphertext, decryption_keys), init_vector);
    *next_init_vector = ciphertext;
    return plaintext;
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in CFB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_encrypt_block_cfb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_xor_block128(aesni_aes256_encrypt_block_(init_vector, encryption_keys), plaintext);
    *next_init_vector = ciphertext;
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in CFB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-256 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_decrypt_block_cfb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block plaintext = aesni_xor_block128(aesni_aes256_encrypt_block_(init_vector, encryption_keys), ciphertext);
    *next_init_vector = ciphertext;
    return plaintext;
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in OFB mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_encrypt_block_ofb(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block tmp = aesni_aes256_encrypt_block_(init_vector, encryption_keys);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, plaintext);
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in OFB mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-256 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_decrypt_block_ofb(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    return aesni_aes256_encrypt_block_ofb(ciphertext, encryption_keys, init_vector, next_init_vector);
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in CTR mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_encrypt_block_ctr(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Aes_Block ciphertext = aesni_xor_block128(plaintext, aesni_aes256_encrypt_block_(init_vector, encryption_keys));
    *next_init_vector = aesni_aes_inc_counter(init_vector);
    return ciphertext;
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in CTR mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-256 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[out] next_init_vector The initialization vector to be used for the next call. Must not be `NULL`.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Aes_Block __fastcall aesni_aes256_decrypt_block_ctr(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Aes_Block init_vector,
    AesNI_Aes_Block* next_init_vector)
{
    return aesni_aes256_encrypt_block_ctr(ciphertext, encryption_keys, init_vector, next_init_vector);
}

#ifdef __cplusplus
}
#endif

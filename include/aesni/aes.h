/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "data.h"

#include <assert.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    AesNI_Block128 keys[11];
}
AesNI_Aes128_RoundKeys;

typedef struct
{
    AesNI_Block128 keys[13];
}
AesNI_Aes192_RoundKeys;

typedef struct
{
    AesNI_Block128 keys[15];
}
AesNI_Aes256_RoundKeys;

void __fastcall aesni_aes128_expand_key_(
    AesNI_Block128 key,
    AesNI_Aes128_RoundKeys* encryption_keys);

void __fastcall aesni_aes192_expand_key_(
    AesNI_Block128 key_lo,
    AesNI_Block128 key_hi,
    AesNI_Aes192_RoundKeys* encryption_keys);

void __fastcall aesni_aes256_expand_key_(
    AesNI_Block128 key_lo,
    AesNI_Block128 key_hi,
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

AesNI_Block128 __fastcall aesni_aes128_encrypt_block_(
    AesNI_Block128 plaintext,
    const AesNI_Aes128_RoundKeys*);

AesNI_Block128 __fastcall aesni_aes192_encrypt_block_(
    AesNI_Block128 plaintext,
    const AesNI_Aes192_RoundKeys*);

AesNI_Block128 __fastcall aesni_aes256_encrypt_block_(
    AesNI_Block128 plaintext,
    const AesNI_Aes256_RoundKeys*);

AesNI_Block128 __fastcall aesni_aes128_decrypt_block_(
    AesNI_Block128 ciphertext,
    const AesNI_Aes128_RoundKeys*);

AesNI_Block128 __fastcall aesni_aes192_decrypt_block_(
    AesNI_Block128 ciphertext,
    const AesNI_Aes192_RoundKeys*);

AesNI_Block128 __fastcall aesni_aes256_decrypt_block_(
    AesNI_Block128 ciphertext,
    const AesNI_Aes256_RoundKeys*);




/**
 * \brief Expands a key schedule for AES-128 encryption.
 *
 * \param[in] key The AES-128 key.
 * \param[out] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 */
static __inline void __fastcall aesni_aes128_expand_key(
    AesNI_Block128 key,
    AesNI_Aes128_RoundKeys* key_schedule)
{
    assert(key_schedule);

    aesni_aes128_expand_key_(key, key_schedule);
}

/**
 * \brief "Inverts" an AES-128 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-128 decryption key schedule. Must not
 * be `NULL`.
 */
static __inline void __fastcall aesni_aes128_derive_decryption_keys(
    const AesNI_Aes128_RoundKeys* key_schedule,
    AesNI_Aes128_RoundKeys* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_aes128_derive_decryption_keys_(key_schedule, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in ECB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_ecb(
    AesNI_Block128 plain,
    const AesNI_Aes128_RoundKeys* key_schedule)
{
    assert(key_schedule);

    return aesni_aes128_encrypt_block_(plain, key_schedule);
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in ECB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-128 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_ecb(
    AesNI_Block128 cipher,
    const AesNI_Aes128_RoundKeys* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_aes128_decrypt_block_(cipher, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in CBC mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The next CBC initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_cbc(
    AesNI_Block128 plain,
    const AesNI_Aes128_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_aes128_encrypt_block_(
        aesni_xor_block128(plain, init_vector),
        key_schedule);
    *next_init_vector = cipher;
    return cipher;
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in CBC mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-128 decryption key schedule. Must not
 * be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The next CBC initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_cbc(
    AesNI_Block128 cipher,
    const AesNI_Aes128_RoundKeys* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = aesni_xor_block128(
        aesni_aes128_decrypt_block_(cipher, inverted_schedule),
        init_vector);
    *next_init_vector = cipher;
    return plain;
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in CFB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The next CFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_cfb(
    AesNI_Block128 plain,
    const AesNI_Aes128_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_xor_block128(
        aesni_aes128_encrypt_block_(init_vector, key_schedule),
        plain);
    *next_init_vector = cipher;
    return cipher;
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in CFB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-128 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The next CFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_cfb(
    AesNI_Block128 cipher,
    const AesNI_Aes128_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = aesni_xor_block128(
        aesni_aes128_encrypt_block_(init_vector, key_schedule),
        cipher);
    *next_init_vector = cipher;
    return plain;
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in OFB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The next OFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_ofb(
    AesNI_Block128 plain,
    const AesNI_Aes128_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes128_encrypt_block_(init_vector, key_schedule);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, plain);
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in OFB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-128 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The next OFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_ofb(
    AesNI_Block128 cipher,
    const AesNI_Aes128_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes128_encrypt_block_(init_vector, key_schedule);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, cipher);
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in CTR mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive
 * calls.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_ctr(
    AesNI_Block128 plain,
    const AesNI_Aes128_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return aesni_xor_block128(
        plain,
        aesni_aes128_encrypt_block_(init_vector, key_schedule));
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in CTR mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-128 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive
 * calls.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_ctr(
    AesNI_Block128 cipher,
    const AesNI_Aes128_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return aesni_xor_block128(
        cipher,
        aesni_aes128_encrypt_block_(init_vector, key_schedule));
}

/**
 * \}
 *
 * \defgroup aesni_block_api_aes192 AES-192
 * \{
 */

/**
 * \brief Expands a key schedule for AES-192 encryption.
 *
 * \param[in] key The AES-192 key. Must not be `NULL`.
 * \param[out] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 */
static __inline void __fastcall aesni_aes192_expand_key(
    AesNI_Block192* key,
    AesNI_Aes192_RoundKeys* key_schedule)
{
    assert(key);
    assert(key_schedule);

    aesni_aes192_expand_key_(key->lo, key->hi, key_schedule);
}

/**
 * \brief "Inverts" an AES-192 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-192 decryption key schedule. Must not
 * be `NULL`.
 */
static __inline void __fastcall aesni_aes192_derive_decryption_keys(
    const AesNI_Aes192_RoundKeys* key_schedule,
    AesNI_Aes192_RoundKeys* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_aes192_derive_decryption_keys_(key_schedule, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in ECB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_ecb(
    AesNI_Block128 plain,
    const AesNI_Aes192_RoundKeys* key_schedule)
{
    assert(key_schedule);

    return aesni_aes192_encrypt_block_(plain, key_schedule);
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in ECB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-192 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_ecb(
    AesNI_Block128 cipher,
    const AesNI_Aes192_RoundKeys* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_aes192_decrypt_block_(cipher, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in CBC mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The next CBC initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_cbc(
    AesNI_Block128 plain,
    const AesNI_Aes192_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_aes192_encrypt_block_(
        aesni_xor_block128(plain, init_vector),
        key_schedule);
    *next_init_vector = cipher;
    return cipher;
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in CBC mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-192 decryption key schedule. Must not
 * be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The next CBC initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_cbc(
    AesNI_Block128 cipher,
    const AesNI_Aes192_RoundKeys* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = aesni_xor_block128(
        aesni_aes192_decrypt_block_(cipher, inverted_schedule),
        init_vector);
    *next_init_vector = cipher;
    return plain;
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in CFB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The next CFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_cfb(
    AesNI_Block128 plain,
    const AesNI_Aes192_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_xor_block128(
        aesni_aes192_encrypt_block_(init_vector, key_schedule),
        plain);
    *next_init_vector = cipher;
    return cipher;
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in CFB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-192 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The next CFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_cfb(
    AesNI_Block128 cipher,
    const AesNI_Aes192_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = aesni_xor_block128(
        aesni_aes192_encrypt_block_(init_vector, key_schedule),
        cipher);
    *next_init_vector = cipher;
    return plain;
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in OFB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The next OFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_ofb(
    AesNI_Block128 plain,
    const AesNI_Aes192_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes192_encrypt_block_(init_vector, key_schedule);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, plain);
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in OFB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-192 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The next OFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_ofb(
    AesNI_Block128 cipher,
    const AesNI_Aes192_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes192_encrypt_block_(init_vector, key_schedule);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, cipher);
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in CTR mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive
 * calls.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_ctr(
    AesNI_Block128 plain,
    const AesNI_Aes192_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return aesni_xor_block128(
        plain,
        aesni_aes192_encrypt_block_(init_vector, key_schedule));
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in CTR mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-192 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive
 * calls.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_ctr(
    AesNI_Block128 cipher,
    const AesNI_Aes192_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return aesni_xor_block128(
        cipher,
        aesni_aes192_encrypt_block_(init_vector, key_schedule));
}

/**
 * \}
 *
 * \defgroup aesni_block_api_aes256 AES-256
 * \{
 */

/**
 * \brief Expands a key schedule for AES-256 encryption.
 *
 * \param[in] key The AES-256 key. Must not be `NULL`.
 * \param[out] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 */
static __inline void __fastcall aesni_aes256_expand_key(
    const AesNI_Block256* key,
    AesNI_Aes256_RoundKeys* key_schedule)
{
    assert(key);
    assert(key_schedule);

    aesni_aes256_expand_key_(key->lo, key->hi, key_schedule);
}

/**
 * \brief "Inverts" an AES-256 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-256 decryption key schedule. Must not
 * be `NULL`.
 */
static __inline void __fastcall aesni_aes256_derive_decryption_keys(
    const AesNI_Aes256_RoundKeys* key_schedule,
    AesNI_Aes256_RoundKeys* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_aes256_derive_decryption_keys_(key_schedule, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in ECB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_ecb(
    AesNI_Block128 plain,
    const AesNI_Aes256_RoundKeys* key_schedule)
{
    assert(key_schedule);

    return aesni_aes256_encrypt_block_(plain, key_schedule);
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in ECB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-256 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_ecb(
    AesNI_Block128 cipher,
    const AesNI_Aes256_RoundKeys* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_aes256_decrypt_block_(cipher, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in CBC mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The next CBC initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_cbc(
    AesNI_Block128 plain,
    const AesNI_Aes256_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_aes256_encrypt_block_(
        aesni_xor_block128(plain, init_vector),
        key_schedule);
    *next_init_vector = cipher;
    return cipher;
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in CBC mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-256 decryption key schedule. Must not
 * be `NULL`.
 * \param[in] init_vector The CBC initialization vector.
 * \param[out] next_init_vector The next CBC initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_cbc(
    AesNI_Block128 cipher,
    const AesNI_Aes256_RoundKeys* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = aesni_xor_block128(
        aesni_aes256_decrypt_block_(cipher, inverted_schedule),
        init_vector);
    *next_init_vector = cipher;
    return plain;
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in CFB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The next CFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_cfb(
    AesNI_Block128 plain,
    const AesNI_Aes256_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_xor_block128(
        aesni_aes256_encrypt_block_(init_vector, key_schedule),
        plain);
    *next_init_vector = cipher;
    return cipher;
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in CFB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-256 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CFB initialization vector.
 * \param[out] next_init_vector The next CFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_cfb(
    AesNI_Block128 cipher,
    const AesNI_Aes256_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = aesni_xor_block128(
        aesni_aes256_encrypt_block_(init_vector, key_schedule),
        cipher);
    *next_init_vector = cipher;
    return plain;
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in OFB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The next OFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_ofb(
    AesNI_Block128 plain,
    const AesNI_Aes256_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes256_encrypt_block_(init_vector, key_schedule);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, plain);
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in OFB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-256 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The OFB initialization vector.
 * \param[out] next_init_vector The next OFB initialization vector to be used
 * as the initialization vector for the next call. Must not be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_ofb(
    AesNI_Block128 cipher,
    const AesNI_Aes256_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes256_encrypt_block_(init_vector, key_schedule);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, cipher);
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in CTR mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive
 * calls.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_ctr(
    AesNI_Block128 plain,
    const AesNI_Aes256_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return aesni_xor_block128(
        plain,
        aesni_aes256_encrypt_block_(init_vector, key_schedule));
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in CTR mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] key_schedule The AES-256 **encryption** key schedule. Must not be
 * `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive
 * calls.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_ctr(
    AesNI_Block128 cipher,
    const AesNI_Aes256_RoundKeys* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return aesni_xor_block128(
        cipher,
        aesni_aes256_encrypt_block_(init_vector, key_schedule));
}

#ifdef __cplusplus
}
#endif

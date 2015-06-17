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
 * \brief Expands an AES-128 key into 10 encryption round keys.
 *
 * \param[in] key The AES-128 key.
 * \param[out] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes128_expand_key(
    AesNI_Block128 key,
    AesNI_Aes128_RoundKeys* encryption_keys)
{
    assert(encryption_keys);

    aesni_aes128_expand_key_(key, encryption_keys);
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
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_ecb(
    AesNI_Block128 plaintext,
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
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_ecb(
    AesNI_Block128 ciphertext,
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
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_cbc(
    AesNI_Block128 plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 ciphertext = aesni_aes128_encrypt_block_(aesni_xor_block128(plaintext, init_vector), encryption_keys);
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
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_cbc(
    AesNI_Block128 ciphertext,
    const AesNI_Aes128_RoundKeys* decryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(decryption_keys);
    assert(next_init_vector);

    AesNI_Block128 plaintext = aesni_xor_block128(aesni_aes128_decrypt_block_(ciphertext, decryption_keys), init_vector);
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
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_cfb(
    AesNI_Block128 plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 ciphertext = aesni_xor_block128(aesni_aes128_encrypt_block_(init_vector, encryption_keys), plaintext);
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
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_cfb(
    AesNI_Block128 ciphertext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 plaintext = aesni_xor_block128(aesni_aes128_encrypt_block_(init_vector, encryption_keys), ciphertext);
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
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_ofb(
    AesNI_Block128 plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes128_encrypt_block_(init_vector, encryption_keys);
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
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_ofb(
    AesNI_Block128 ciphertext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes128_encrypt_block_(init_vector, encryption_keys);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, ciphertext);
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in CTR mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-128 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive calls.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_encrypt_block_ctr(
    AesNI_Block128 plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(encryption_keys);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);

    return aesni_xor_block128(plaintext, aesni_aes128_encrypt_block_(init_vector, encryption_keys));
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in CTR mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-128 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive calls.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes128_decrypt_block_ctr(
    AesNI_Block128 ciphertext,
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(encryption_keys);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);

    return aesni_xor_block128(ciphertext, aesni_aes128_encrypt_block_(init_vector, encryption_keys));
}

/**
 * \brief Expands an AES-192 key into 12 encryption round keys.
 *
 * \param[in] key The AES-192 key.
 * \param[out] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes192_expand_key(
    AesNI_Block192* key,
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
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_ecb(
    AesNI_Block128 plaintext,
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
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_ecb(
    AesNI_Block128 ciphertext,
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
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_cbc(
    AesNI_Block128 plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 ciphertext = aesni_aes192_encrypt_block_(aesni_xor_block128(plaintext, init_vector), encryption_keys);
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
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_cbc(
    AesNI_Block128 ciphertext,
    const AesNI_Aes192_RoundKeys* decryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(decryption_keys);
    assert(next_init_vector);

    AesNI_Block128 plaintext = aesni_xor_block128(aesni_aes192_decrypt_block_(ciphertext, decryption_keys), init_vector);
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
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_cfb(
    AesNI_Block128 plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 ciphertext = aesni_xor_block128(aesni_aes192_encrypt_block_(init_vector, encryption_keys), plaintext);
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
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_cfb(
    AesNI_Block128 ciphertext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 plaintext = aesni_xor_block128(aesni_aes192_encrypt_block_(init_vector, encryption_keys), ciphertext);
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
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_ofb(
    AesNI_Block128 plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes192_encrypt_block_(init_vector, encryption_keys);
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
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_ofb(
    AesNI_Block128 ciphertext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes192_encrypt_block_(init_vector, encryption_keys);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, ciphertext);
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in CTR mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-192 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive calls.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_encrypt_block_ctr(
    AesNI_Block128 plaintext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(encryption_keys);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);

    return aesni_xor_block128(plaintext, aesni_aes192_encrypt_block_(init_vector, encryption_keys));
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in CTR mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-192 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive calls.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes192_decrypt_block_ctr(
    AesNI_Block128 ciphertext,
    const AesNI_Aes192_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(encryption_keys);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);

    return aesni_xor_block128(ciphertext, aesni_aes192_encrypt_block_(init_vector, encryption_keys));
}

/**
 * \brief Expands an AES-256 key into 14 encryption round keys.
 *
 * \param[in] key The AES-256 key.
 * \param[out] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 */
static __inline void __fastcall aesni_aes256_expand_key(
    const AesNI_Block256* key,
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
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_ecb(
    AesNI_Block128 plaintext,
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
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_ecb(
    AesNI_Block128 ciphertext,
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
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_cbc(
    AesNI_Block128 plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 ciphertext = aesni_aes256_encrypt_block_(aesni_xor_block128(plaintext, init_vector), encryption_keys);
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
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_cbc(
    AesNI_Block128 ciphertext,
    const AesNI_Aes256_RoundKeys* decryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(decryption_keys);
    assert(next_init_vector);

    AesNI_Block128 plaintext = aesni_xor_block128(aesni_aes256_decrypt_block_(ciphertext, decryption_keys), init_vector);
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
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_cfb(
    AesNI_Block128 plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 ciphertext = aesni_xor_block128(aesni_aes256_encrypt_block_(init_vector, encryption_keys), plaintext);
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
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_cfb(
    AesNI_Block128 ciphertext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 plaintext = aesni_xor_block128(aesni_aes256_encrypt_block_(init_vector, encryption_keys), ciphertext);
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
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_ofb(
    AesNI_Block128 plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes256_encrypt_block_(init_vector, encryption_keys);
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
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_ofb(
    AesNI_Block128 ciphertext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(encryption_keys);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_aes256_encrypt_block_(init_vector, encryption_keys);
    *next_init_vector = tmp;
    return aesni_xor_block128(tmp, ciphertext);
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in CTR mode of operation.
 *
 * \param[in] plaintext The plaintext to be encrypted.
 * \param[in] encryption_keys The AES-256 encryption round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive calls.
 *
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_encrypt_block_ctr(
    AesNI_Block128 plaintext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(encryption_keys);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);

    return aesni_xor_block128(plaintext, aesni_aes256_encrypt_block_(init_vector, encryption_keys));
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in CTR mode of operation.
 *
 * \param[in] ciphertext The ciphertext to be decrypted.
 * \param[in] encryption_keys The AES-256 **encryption** round keys. Must not be `NULL`.
 * \param[in] init_vector The CTR initialization vector.
 * \param[in] counter The counter, typically incremented between consecutive calls.
 *
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_aes256_decrypt_block_ctr(
    AesNI_Block128 ciphertext,
    const AesNI_Aes256_RoundKeys* encryption_keys,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(encryption_keys);

    init_vector = aesni_le2be128(init_vector);
    init_vector = _mm_add_epi32(init_vector, aesni_make_block128(0, 0, 0, counter));
    init_vector = aesni_be2le128(init_vector);

    return aesni_xor_block128(ciphertext, aesni_aes256_encrypt_block_(init_vector, encryption_keys));
}

#ifdef __cplusplus
}
#endif

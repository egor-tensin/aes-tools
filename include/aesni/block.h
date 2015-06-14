/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 *
 * \brief Declares 128-bit block encryption/decryption functions.
 */

#pragma once

/**
 * \defgroup aesni_block_api Block API
 * \brief 128-bit block encryption/decryption functions.
 * \ingroup aesni
 * \{
 *
 * For each of AES-128/192/256, two functions are defined:
 *
 * * a key schedule "expansion" function to prepare for encryption,
 * * a key schedule "reversion" function to prepare for decryption.
 *
 * The functions, respectively, are:
 *
 * * `aesni_expand_key_scheduleNNN`,
 * * `aesni_reverse_key_scheduleNNN`,
 *
 * where `NNN` is either `128`, `192` or `256`.
 *
 * For each of AES-128/192/256 and modes of operation ECB, CBC, CFB, OFB, and
 * CTR, two functions are defined:
 *
 * * a 128-bit block encryption function,
 * * a 128-bit block decryption function.
 *
 * The functions, respectively, are:
 *
 * * `aesni_encrypt_block_XXXNNN`,
 * * `aesni_decrypt_block_XXXNNN`,
 *
 * where `XXX` is either `ecb`, `cbc`, `cfb`, `ofb` or `ctr`, and `NNN` is
 * either `128`, `192` or `256`.
 */

#include "data.h"
#include "raw.h"

#include <assert.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * \defgroup aesni_block_api_aes128 AES-128
 * \{
 */

/**
 * \brief Expands a key schedule for AES-128 encryption.
 *
 * \param[in] key The AES-128 key.
 * \param[out] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 */
static __inline void __fastcall aesni_expand_key_schedule128(
    AesNI_Block128 key,
    AesNI_KeySchedule128* key_schedule)
{
    assert(key_schedule);

    aesni_raw_expand_key_schedule128(key, key_schedule);
}

/**
 * \brief "Inverts" an AES-128 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-128 decryption key schedule. Must not
 * be `NULL`.
 */
static __inline void __fastcall aesni_invert_key_schedule128(
    AesNI_KeySchedule128* key_schedule,
    AesNI_KeySchedule128* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_raw_invert_key_schedule128(key_schedule, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-128 in ECB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ecb128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule)
{
    assert(key_schedule);

    return aesni_raw_encrypt_block128(plain, key_schedule);
}

/**
 * \brief Decrypts a 128-bit block using AES-128 in ECB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-128 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ecb128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_raw_decrypt_block128(cipher, inverted_schedule);
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cbc128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_raw_encrypt_block128(
        _mm_xor_si128(plain, init_vector),
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cbc128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(
        aesni_raw_decrypt_block128(cipher, inverted_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cfb128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = _mm_xor_si128(
        aesni_raw_encrypt_block128(init_vector, key_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cfb128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(
        aesni_raw_encrypt_block128(init_vector, key_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ofb128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block128(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, plain);
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ofb128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block128(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, cipher);
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ctr128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return _mm_xor_si128(
        plain,
        aesni_raw_encrypt_block128(init_vector, key_schedule));
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ctr128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return _mm_xor_si128(
        cipher,
        aesni_raw_encrypt_block128(init_vector, key_schedule));
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
static __inline void __fastcall aesni_expand_key_schedule192(
    AesNI_Block192* key,
    AesNI_KeySchedule192* key_schedule)
{
    assert(key);
    assert(key_schedule);

    aesni_raw_expand_key_schedule192(key->lo, key->hi, key_schedule);
}

/**
 * \brief "Inverts" an AES-192 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-192 decryption key schedule. Must not
 * be `NULL`.
 */
static __inline void __fastcall aesni_invert_key_schedule192(
    AesNI_KeySchedule192* key_schedule,
    AesNI_KeySchedule192* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_raw_invert_key_schedule192(key_schedule, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-192 in ECB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ecb192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule)
{
    assert(key_schedule);

    return aesni_raw_encrypt_block192(plain, key_schedule);
}

/**
 * \brief Decrypts a 128-bit block using AES-192 in ECB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-192 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ecb192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_raw_decrypt_block192(cipher, inverted_schedule);
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cbc192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_raw_encrypt_block192(
        _mm_xor_si128(plain, init_vector),
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cbc192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(
        aesni_raw_decrypt_block192(cipher, inverted_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cfb192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = _mm_xor_si128(
        aesni_raw_encrypt_block192(init_vector, key_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cfb192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(
        aesni_raw_encrypt_block192(init_vector, key_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ofb192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block192(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, plain);
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ofb192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block192(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, cipher);
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ctr192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return _mm_xor_si128(
        plain,
        aesni_raw_encrypt_block192(init_vector, key_schedule));
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ctr192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return _mm_xor_si128(
        cipher,
        aesni_raw_encrypt_block192(init_vector, key_schedule));
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
static __inline void __fastcall aesni_expand_key_schedule256(
    AesNI_Block256* key,
    AesNI_KeySchedule256* key_schedule)
{
    assert(key);
    assert(key_schedule);

    aesni_raw_expand_key_schedule256(key->lo, key->hi, key_schedule);
}

/**
 * \brief "Inverts" an AES-256 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-256 decryption key schedule. Must not
 * be `NULL`.
 */
static __inline void __fastcall aesni_invert_key_schedule256(
    AesNI_KeySchedule256* key_schedule,
    AesNI_KeySchedule256* inverted_schedule)
{
    assert(key_schedule);
    assert(inverted_schedule);

    aesni_raw_invert_key_schedule256(key_schedule, inverted_schedule);
}

/**
 * \brief Encrypts a 128-bit block using AES-256 in ECB mode of operation.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ecb256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule)
{
    assert(key_schedule);

    return aesni_raw_encrypt_block256(plain, key_schedule);
}

/**
 * \brief Decrypts a 128-bit block using AES-256 in ECB mode of operation.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-256 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ecb256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* inverted_schedule)
{
    assert(inverted_schedule);

    return aesni_raw_decrypt_block256(cipher, inverted_schedule);
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cbc256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = aesni_raw_encrypt_block256(
        _mm_xor_si128(plain, init_vector),
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cbc256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* inverted_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(inverted_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(
        aesni_raw_decrypt_block256(cipher, inverted_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_cfb256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 cipher = _mm_xor_si128(
        aesni_raw_encrypt_block256(init_vector, key_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_cfb256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 plain = _mm_xor_si128(
        aesni_raw_encrypt_block256(init_vector, key_schedule),
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ofb256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block256(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, plain);
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ofb256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    AesNI_Block128* next_init_vector)
{
    assert(key_schedule);
    assert(next_init_vector);

    AesNI_Block128 tmp = aesni_raw_encrypt_block256(init_vector, key_schedule);
    *next_init_vector = tmp;
    return _mm_xor_si128(tmp, cipher);
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
static __inline AesNI_Block128 __fastcall aesni_encrypt_block_ctr256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return _mm_xor_si128(
        plain,
        aesni_raw_encrypt_block256(init_vector, key_schedule));
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
static __inline AesNI_Block128 __fastcall aesni_decrypt_block_ctr256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* key_schedule,
    AesNI_Block128 init_vector,
    int counter)
{
    assert(key_schedule);

    init_vector = aesni_be2le128(_mm_add_epi32(
        aesni_le2be128(init_vector),
        aesni_make_block128(0, 0, 0, counter)));

    return _mm_xor_si128(
        cipher,
        aesni_raw_encrypt_block256(init_vector, key_schedule));
}

/**
 * \}
 */

#ifdef __cplusplus
}
#endif

/**
 * \}
 */

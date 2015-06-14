/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 *
 * \brief *Don't use.* Declares "raw" 128-bit block encryption/decryption
 * functions.
 */

#pragma once

/**
 * \defgroup aesni_raw_api Raw API
 * \brief *Don't use.* "Raw" 128-bit block encryption/decryption functions.
 * \ingroup aesni
 * \{
 *
 * For each of AES-128/192/256, four functions are defined:
 *
 * * a key schedule "expansion" function to prepare for encryption,
 * * a 128-bit block encryption function using the key schedule,
 * * a key schedule "inversion" function to prepare for decryption,
 * * a 128-bit block decryption function using the "inverted" key schedule.
 *
 * The functions, respectively, are:
 *
 * * `aesni_raw_expand_key_scheduleNNN`,
 * * `aesni_raw_encrypt_blockNNN`,
 * * `aesni_raw_invert_key_scheduleNNN`,
 * * `aesni_raw_decrypt_blockNNN`,
 *
 * where `NNN` is key length (either `128`, `192` or `256`).
 */

#include "data.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * \defgroup aesni_raw_api_aes128 AES-128
 * \{
 */

/**
 * \brief Expands a key schedule for AES-128 encryption.
 *
 * \param[in] key The AES-128 key.
 * \param[out] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 */
void __fastcall aesni_raw_expand_key_schedule128(
    AesNI_Block128 key,
    AesNI_KeySchedule128* key_schedule);

/**
 * \brief "Inverts" an AES-128 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-128 decryption key schedule. Must not
 * be `NULL`.
 */
void __fastcall aesni_raw_invert_key_schedule128(
    AesNI_KeySchedule128* key_schedule,
    AesNI_KeySchedule128* inverted_schedule);

/**
 * \brief Encrypts a 128-bit block using AES-128.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-128 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
AesNI_Block128 __fastcall aesni_raw_encrypt_block128(
    AesNI_Block128 plain,
    AesNI_KeySchedule128* key_schedule);

/**
 * \brief Decrypts a 128-bit block using AES-128.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-128 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
AesNI_Block128 __fastcall aesni_raw_decrypt_block128(
    AesNI_Block128 cipher,
    AesNI_KeySchedule128* inverted_schedule);

/**
 * \}
 *
 * \defgroup aesni_raw_api_aes192 AES-192
 * \{
 */

/**
 * \brief Expands a key schedule for AES-192 encryption.
 *
 * \param[in] key_lo The least significant part of the AES-192 key.
 * \param[in] key_hi The most significant part of the AES-192 key.
 * \param[out] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 */
void __fastcall aesni_raw_expand_key_schedule192(
    AesNI_Block128 key_lo,
    AesNI_Block128 key_hi,
    AesNI_KeySchedule192* key_schedule);

/**
 * \brief "Inverts" an AES-192 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-192 decryption key schedule. Must not
 * be `NULL`.
 */
void __fastcall aesni_raw_invert_key_schedule192(
    AesNI_KeySchedule192* key_schedule,
    AesNI_KeySchedule192* inverted_schedule);

/**
 * \brief Encrypts a 128-bit block using AES-192.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-192 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
AesNI_Block128 __fastcall aesni_raw_encrypt_block192(
    AesNI_Block128 plain,
    AesNI_KeySchedule192* key_schedule);

/**
 * \brief Decrypts a 128-bit block using AES-192.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-192 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
AesNI_Block128 __fastcall aesni_raw_decrypt_block192(
    AesNI_Block128 cipher,
    AesNI_KeySchedule192* inverted_schedule);

/**
 * \}
 *
 * \defgroup aesni_raw_api_aes256 AES-256
 * \{
 */

/**
 * \brief Expands a key schedule for AES-256 encryption.
 *
 * \param[in] key_lo The least significant part of the AES-256 key.
 * \param[in] key_hi The most significant part of the AES-256 key.
 * \param[out] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 */
void __fastcall aesni_raw_expand_key_schedule256(
    AesNI_Block128 key_lo,
    AesNI_Block128 key_hi,
    AesNI_KeySchedule256* key_schedule);

/**
 * \brief "Inverts" a AES-256 key schedule to prepare for decryption.
 *
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \param[out] inverted_schedule The AES-256 decryption key schedule. Must not
 * be `NULL`.
 */
void __fastcall aesni_raw_invert_key_schedule256(
    AesNI_KeySchedule256* key_schedule,
    AesNI_KeySchedule256* inverted_schedule);

/**
 * \brief Encrypts a 128-bit block using AES-256.
 *
 * \param[in] plain The plaintext to be encrypted.
 * \param[in] key_schedule The AES-256 encryption key schedule. Must not be
 * `NULL`.
 * \return The encrypted 128-bit ciphertext.
 */
AesNI_Block128 __fastcall aesni_raw_encrypt_block256(
    AesNI_Block128 plain,
    AesNI_KeySchedule256* key_schedule);

/**
 * \brief Decrypts a 128-bit block using AES-256.
 *
 * \param[in] cipher The ciphertext to be decrypted.
 * \param[in] inverted_schedule The AES-256 decryption key schedule. Must not
 * be `NULL`.
 * \return The decrypted 128-bit plaintext.
 */
AesNI_Block128 __fastcall aesni_raw_decrypt_block256(
    AesNI_Block128 cipher,
    AesNI_KeySchedule256* inverted_schedule);

/**
 * \}
 */

#ifdef __cplusplus
}
#endif

/**
 * \}
 */

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <stdlib.h>
#include <string.h>

static AesNI_StatusCode aesni_box_derive_params_aes128(
    const AesNI_BoxKey* box_key,
    AesNI_BoxEncryptionRoundKeys* encryption_keys,
    AesNI_BoxDecryptionRoundKeys* decryption_keys,
    AesNI_ErrorDetails* err_details)
{
    aesni_AES128_expand_key_(
        box_key->aes128_key.key,
        &encryption_keys->aes128_encryption_keys);
    aesni_AES128_derive_decryption_keys_(
        &encryption_keys->aes128_encryption_keys,
        &decryption_keys->aes128_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_derive_params_aes192(
    const AesNI_BoxKey* box_key,
    AesNI_BoxEncryptionRoundKeys* encryption_keys,
    AesNI_BoxDecryptionRoundKeys* decryption_keys,
    AesNI_ErrorDetails* err_details)
{
    aesni_AES192_expand_key_(
        box_key->aes192_key.lo,
        box_key->aes192_key.hi,
        &encryption_keys->aes192_encryption_keys);
    aesni_AES192_derive_decryption_keys_(
        &encryption_keys->aes192_encryption_keys,
        &decryption_keys->aes192_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_derive_params_aes256(
    const AesNI_BoxKey* box_key,
    AesNI_BoxEncryptionRoundKeys* encryption_keys,
    AesNI_BoxDecryptionRoundKeys* decryption_keys,
    AesNI_ErrorDetails* err_details)
{
    aesni_AES256_expand_key_(
        box_key->aes256_key.lo,
        box_key->aes256_key.hi,
        &encryption_keys->aes256_encryption_keys);
    aesni_AES256_derive_decryption_keys_(
        &encryption_keys->aes256_encryption_keys,
        &decryption_keys->aes256_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_parse_block_aes(
    AesNI_BoxBlock* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");

    return aesni_AES_parse_block(&dest->aes_block, src, err_details);
}

static AesNI_StatusCode aesni_box_parse_key_aes128(
    AesNI_BoxKey* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");

    return aesni_AES128_parse_key(&dest->aes128_key, src, err_details);
}

static AesNI_StatusCode aesni_box_parse_key_aes192(
    AesNI_BoxKey* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");

    return aesni_AES192_parse_key(&dest->aes192_key, src, err_details);
}

static AesNI_StatusCode aesni_box_parse_key_aes256(
    AesNI_BoxKey* dest,
    const char* src,
    AesNI_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");

    return aesni_AES256_parse_key(&dest->aes256_key, src, err_details);
}

static AesNI_StatusCode aesni_box_format_block_aes(
    AesNI_BoxBlockString* dest,
    const AesNI_BoxBlock* src,
    AesNI_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aesni_error_null_argument(err_details, "src");

    return aesni_AES128_format_block(&dest->aes, &src->aes_block, err_details);
}

static AesNI_StatusCode aesni_box_format_key_aes128(
    AesNI_BoxKeyString* dest,
    const AesNI_BoxKey* src,
    AesNI_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aesni_error_null_argument(err_details, "src");

    return aesni_AES128_format_key(&dest->aes128, &src->aes128_key, err_details);
}

static AesNI_StatusCode aesni_box_format_key_aes192(
    AesNI_BoxKeyString* dest,
    const AesNI_BoxKey* src,
    AesNI_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aesni_error_null_argument(err_details, "src");

    return aesni_AES192_format_key(&dest->aes192, &src->aes192_key, err_details);
}

static AesNI_StatusCode aesni_box_format_key_aes256(
    AesNI_BoxKeyString* dest,
    const AesNI_BoxKey* src,
    AesNI_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aesni_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aesni_error_null_argument(err_details, "src");

    return aesni_AES256_format_key(&dest->aes256, &src->aes256_key, err_details);
}

static AesNI_StatusCode aesni_box_xor_block_aes(
    AesNI_BoxBlock* dest,
    const AesNI_BoxBlock* src,
    AesNI_ErrorDetails* err_details)
{

    dest->aes_block = aesni_AES_xor_blocks(dest->aes_block, src->aes_block);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_inc_block_aes(
    AesNI_BoxBlock* ctr,
    AesNI_ErrorDetails* err_details)
{
    ctr->aes_block = aesni_AES_inc_block(ctr->aes_block);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_get_block_size_aes(
    size_t* block_size,
    AesNI_ErrorDetails* err_details)
{
    *block_size = 16;
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_store_block_aes(
    void* dest,
    const AesNI_BoxBlock* src,
    AesNI_ErrorDetails* err_details)
{
    aesni_store_block128(dest, src->aes_block);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_load_block_aes(
    AesNI_BoxBlock* dest,
    const void* src,
    AesNI_ErrorDetails* err_details)
{
    dest->aes_block = aesni_load_block128(src);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_encrypt_block_aes128(
    const AesNI_BoxBlock* input,
    const AesNI_BoxEncryptionRoundKeys* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_AES128_encrypt_block_(
        input->aes_block,
        &params->aes128_encryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_block_aes128(
    const AesNI_BoxBlock* input,
    const AesNI_BoxDecryptionRoundKeys* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_AES128_decrypt_block_(
        input->aes_block,
        &params->aes128_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_encrypt_block_aes192(
    const AesNI_BoxBlock* input,
    const AesNI_BoxEncryptionRoundKeys* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_AES192_encrypt_block_(
        input->aes_block,
        &params->aes192_encryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_block_aes192(
    const AesNI_BoxBlock* input,
    const AesNI_BoxDecryptionRoundKeys* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_AES192_decrypt_block_(
        input->aes_block,
        &params->aes192_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_encrypt_block_aes256(
    const AesNI_BoxBlock* input,
    const AesNI_BoxEncryptionRoundKeys* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_AES256_encrypt_block_(
        input->aes_block,
        &params->aes256_encryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_block_aes256(
    const AesNI_BoxBlock* input,
    const AesNI_BoxDecryptionRoundKeys* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_AES256_decrypt_block_(
        input->aes_block,
        &params->aes256_decryption_keys);
    return AESNI_SUCCESS;
}

AesNI_BoxAlgorithmInterface aesni_box_algorithm_aes128 =
{
    &aesni_box_derive_params_aes128,
    &aesni_box_parse_block_aes,
    &aesni_box_parse_key_aes128,
    &aesni_box_format_block_aes,
    &aesni_box_format_key_aes128,
    &aesni_box_encrypt_block_aes128,
    &aesni_box_decrypt_block_aes128,
    &aesni_box_xor_block_aes,
    &aesni_box_inc_block_aes,
    &aesni_box_get_block_size_aes,
    &aesni_box_store_block_aes,
    &aesni_box_load_block_aes,
};

AesNI_BoxAlgorithmInterface aesni_box_algorithm_aes192 =
{
    &aesni_box_derive_params_aes192,
    &aesni_box_parse_block_aes,
    &aesni_box_parse_key_aes192,
    &aesni_box_format_block_aes,
    &aesni_box_format_key_aes192,
    &aesni_box_encrypt_block_aes192,
    &aesni_box_decrypt_block_aes192,
    &aesni_box_xor_block_aes,
    &aesni_box_inc_block_aes,
    &aesni_box_get_block_size_aes,
    &aesni_box_store_block_aes,
    &aesni_box_load_block_aes,
};

AesNI_BoxAlgorithmInterface aesni_box_algorithm_aes256 =
{
    &aesni_box_derive_params_aes256,
    &aesni_box_parse_block_aes,
    &aesni_box_parse_key_aes256,
    &aesni_box_format_block_aes,
    &aesni_box_format_key_aes256,
    &aesni_box_encrypt_block_aes256,
    &aesni_box_decrypt_block_aes256,
    &aesni_box_xor_block_aes,
    &aesni_box_inc_block_aes,
    &aesni_box_get_block_size_aes,
    &aesni_box_store_block_aes,
    &aesni_box_load_block_aes,
};

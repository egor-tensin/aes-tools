/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aes/all.h>

#include <stdlib.h>
#include <string.h>

static AES_StatusCode aes_box_derive_params_aes128(
    const AES_BoxKey* box_key,
    AES_BoxEncryptionRoundKeys* encryption_keys,
    AES_BoxDecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details)
{
    aes_AES128_expand_key_(
        box_key->aes128_key.key,
        &encryption_keys->aes128_encryption_keys);
    aes_AES128_derive_decryption_keys_(
        &encryption_keys->aes128_encryption_keys,
        &decryption_keys->aes128_decryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_derive_params_aes192(
    const AES_BoxKey* box_key,
    AES_BoxEncryptionRoundKeys* encryption_keys,
    AES_BoxDecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details)
{
    aes_AES192_expand_key_(
        box_key->aes192_key.lo,
        box_key->aes192_key.hi,
        &encryption_keys->aes192_encryption_keys);
    aes_AES192_derive_decryption_keys_(
        &encryption_keys->aes192_encryption_keys,
        &decryption_keys->aes192_decryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_derive_params_aes256(
    const AES_BoxKey* box_key,
    AES_BoxEncryptionRoundKeys* encryption_keys,
    AES_BoxDecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details)
{
    aes_AES256_expand_key_(
        box_key->aes256_key.lo,
        box_key->aes256_key.hi,
        &encryption_keys->aes256_encryption_keys);
    aes_AES256_derive_decryption_keys_(
        &encryption_keys->aes256_encryption_keys,
        &decryption_keys->aes256_decryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_parse_block_aes(
    AES_BoxBlock* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes_AES_parse_block(&dest->aes_block, src, err_details);
}

static AES_StatusCode aes_box_parse_key_aes128(
    AES_BoxKey* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes_AES128_parse_key(&dest->aes128_key, src, err_details);
}

static AES_StatusCode aes_box_parse_key_aes192(
    AES_BoxKey* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes_AES192_parse_key(&dest->aes192_key, src, err_details);
}

static AES_StatusCode aes_box_parse_key_aes256(
    AES_BoxKey* dest,
    const char* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes_AES256_parse_key(&dest->aes256_key, src, err_details);
}

static AES_StatusCode aes_box_format_block_aes(
    AES_BoxBlockString* dest,
    const AES_BoxBlock* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_AES128_format_block(&dest->aes, &src->aes_block, err_details);
}

static AES_StatusCode aes_box_format_key_aes128(
    AES_BoxKeyString* dest,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_AES128_format_key(&dest->aes128, &src->aes128_key, err_details);
}

static AES_StatusCode aes_box_format_key_aes192(
    AES_BoxKeyString* dest,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_AES192_format_key(&dest->aes192, &src->aes192_key, err_details);
}

static AES_StatusCode aes_box_format_key_aes256(
    AES_BoxKeyString* dest,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_AES256_format_key(&dest->aes256, &src->aes256_key, err_details);
}

static AES_StatusCode aes_box_xor_block_aes(
    AES_BoxBlock* dest,
    const AES_BoxBlock* src,
    AES_ErrorDetails* err_details)
{

    dest->aes_block = aes_AES_xor_blocks(dest->aes_block, src->aes_block);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_inc_block_aes(
    AES_BoxBlock* ctr,
    AES_ErrorDetails* err_details)
{
    ctr->aes_block = aes_AES_inc_block(ctr->aes_block);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_get_block_size_aes(
    size_t* block_size,
    AES_ErrorDetails* err_details)
{
    *block_size = 16;
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_store_block_aes(
    void* dest,
    const AES_BoxBlock* src,
    AES_ErrorDetails* err_details)
{
    aes_store_block128(dest, src->aes_block);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_load_block_aes(
    AES_BoxBlock* dest,
    const void* src,
    AES_ErrorDetails* err_details)
{
    dest->aes_block = aes_load_block128(src);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_encrypt_block_aes128(
    const AES_BoxBlock* input,
    const AES_BoxEncryptionRoundKeys* params,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    output->aes_block = aes_AES128_encrypt_block_(
        input->aes_block,
        &params->aes128_encryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_decrypt_block_aes128(
    const AES_BoxBlock* input,
    const AES_BoxDecryptionRoundKeys* params,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    output->aes_block = aes_AES128_decrypt_block_(
        input->aes_block,
        &params->aes128_decryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_encrypt_block_aes192(
    const AES_BoxBlock* input,
    const AES_BoxEncryptionRoundKeys* params,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    output->aes_block = aes_AES192_encrypt_block_(
        input->aes_block,
        &params->aes192_encryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_decrypt_block_aes192(
    const AES_BoxBlock* input,
    const AES_BoxDecryptionRoundKeys* params,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    output->aes_block = aes_AES192_decrypt_block_(
        input->aes_block,
        &params->aes192_decryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_encrypt_block_aes256(
    const AES_BoxBlock* input,
    const AES_BoxEncryptionRoundKeys* params,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    output->aes_block = aes_AES256_encrypt_block_(
        input->aes_block,
        &params->aes256_encryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_decrypt_block_aes256(
    const AES_BoxBlock* input,
    const AES_BoxDecryptionRoundKeys* params,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    output->aes_block = aes_AES256_decrypt_block_(
        input->aes_block,
        &params->aes256_decryption_keys);
    return AES_SUCCESS;
}

AES_BoxAlgorithmInterface aes_box_algorithm_aes128 =
{
    &aes_box_derive_params_aes128,
    &aes_box_parse_block_aes,
    &aes_box_parse_key_aes128,
    &aes_box_format_block_aes,
    &aes_box_format_key_aes128,
    &aes_box_encrypt_block_aes128,
    &aes_box_decrypt_block_aes128,
    &aes_box_xor_block_aes,
    &aes_box_inc_block_aes,
    &aes_box_get_block_size_aes,
    &aes_box_store_block_aes,
    &aes_box_load_block_aes,
};

AES_BoxAlgorithmInterface aes_box_algorithm_aes192 =
{
    &aes_box_derive_params_aes192,
    &aes_box_parse_block_aes,
    &aes_box_parse_key_aes192,
    &aes_box_format_block_aes,
    &aes_box_format_key_aes192,
    &aes_box_encrypt_block_aes192,
    &aes_box_decrypt_block_aes192,
    &aes_box_xor_block_aes,
    &aes_box_inc_block_aes,
    &aes_box_get_block_size_aes,
    &aes_box_store_block_aes,
    &aes_box_load_block_aes,
};

AES_BoxAlgorithmInterface aes_box_algorithm_aes256 =
{
    &aes_box_derive_params_aes256,
    &aes_box_parse_block_aes,
    &aes_box_parse_key_aes256,
    &aes_box_format_block_aes,
    &aes_box_format_key_aes256,
    &aes_box_encrypt_block_aes256,
    &aes_box_decrypt_block_aes256,
    &aes_box_xor_block_aes,
    &aes_box_inc_block_aes,
    &aes_box_get_block_size_aes,
    &aes_box_store_block_aes,
    &aes_box_load_block_aes,
};

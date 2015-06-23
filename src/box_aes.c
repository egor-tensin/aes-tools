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
    const AesNI_BoxAlgorithmParams* algorithm_params,
    AesNI_BoxEncryptionParams* encrypt_params,
    AesNI_BoxDecryptionParams* decrypt_params,
    AesNI_ErrorDetails* err_details)
{
    aesni_aes128_expand_key_(
        algorithm_params->aes128_key.key,
        &encrypt_params->aes128_encryption_keys);
    aesni_aes128_derive_decryption_keys_(
        &encrypt_params->aes128_encryption_keys,
        &decrypt_params->aes128_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_derive_params_aes192(
    const AesNI_BoxAlgorithmParams* algorithm_params,
    AesNI_BoxEncryptionParams* encrypt_params,
    AesNI_BoxDecryptionParams* decrypt_params,
    AesNI_ErrorDetails* err_details)
{
    aesni_aes192_expand_key_(
        algorithm_params->aes192_key.lo,
        algorithm_params->aes192_key.hi,
        &encrypt_params->aes192_encryption_keys);
    aesni_aes192_derive_decryption_keys_(
        &encrypt_params->aes192_encryption_keys,
        &decrypt_params->aes192_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_derive_params_aes256(
    const AesNI_BoxAlgorithmParams* algorithm_params,
    AesNI_BoxEncryptionParams* encrypt_params,
    AesNI_BoxDecryptionParams* decrypt_params,
    AesNI_ErrorDetails* err_details)
{
    aesni_aes256_expand_key_(
        algorithm_params->aes256_key.lo,
        algorithm_params->aes256_key.hi,
        &encrypt_params->aes256_encryption_keys);
    aesni_aes256_derive_decryption_keys_(
        &encrypt_params->aes256_encryption_keys,
        &decrypt_params->aes256_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_xor_block_aes(
    AesNI_BoxBlock* dest,
    const AesNI_BoxBlock* src,
    AesNI_ErrorDetails* err_details)
{
    dest->aes_block = aesni_xor_block128(dest->aes_block, src->aes_block);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_next_counter_aes(
    AesNI_BoxBlock* ctr,
    AesNI_ErrorDetails* err_details)
{
    ctr->aes_block = aesni_aes_inc_block(ctr->aes_block);
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
    const AesNI_BoxEncryptionParams* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_aes128_encrypt_block_(
        input->aes_block,
        &params->aes128_encryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_block_aes128(
    const AesNI_BoxBlock* input,
    const AesNI_BoxDecryptionParams* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_aes128_decrypt_block_(
        input->aes_block,
        &params->aes128_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_encrypt_block_aes192(
    const AesNI_BoxBlock* input,
    const AesNI_BoxEncryptionParams* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_aes192_encrypt_block_(
        input->aes_block,
        &params->aes192_encryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_block_aes192(
    const AesNI_BoxBlock* input,
    const AesNI_BoxDecryptionParams* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_aes192_decrypt_block_(
        input->aes_block,
        &params->aes192_decryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_encrypt_block_aes256(
    const AesNI_BoxBlock* input,
    const AesNI_BoxEncryptionParams* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_aes256_encrypt_block_(
        input->aes_block,
        &params->aes256_encryption_keys);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_block_aes256(
    const AesNI_BoxBlock* input,
    const AesNI_BoxDecryptionParams* params,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_aes256_decrypt_block_(
        input->aes_block,
        &params->aes256_decryption_keys);
    return AESNI_SUCCESS;
}

AesNI_BoxAlgorithmInterface aesni_box_algorithm_aes128 =
{
    &aesni_box_derive_params_aes128,
    &aesni_box_encrypt_block_aes128,
    &aesni_box_decrypt_block_aes128,
    &aesni_box_xor_block_aes,
    &aesni_box_next_counter_aes,
    &aesni_box_get_block_size_aes,
    &aesni_box_store_block_aes,
    &aesni_box_load_block_aes,
};

AesNI_BoxAlgorithmInterface aesni_box_algorithm_aes192 =
{
    &aesni_box_derive_params_aes192,
    &aesni_box_encrypt_block_aes192,
    &aesni_box_decrypt_block_aes192,
    &aesni_box_xor_block_aes,
    &aesni_box_next_counter_aes,
    &aesni_box_get_block_size_aes,
    &aesni_box_store_block_aes,
    &aesni_box_load_block_aes,
};

AesNI_BoxAlgorithmInterface aesni_box_algorithm_aes256 =
{
    &aesni_box_derive_params_aes256,
    &aesni_box_encrypt_block_aes256,
    &aesni_box_decrypt_block_aes256,
    &aesni_box_xor_block_aes,
    &aesni_box_next_counter_aes,
    &aesni_box_get_block_size_aes,
    &aesni_box_store_block_aes,
    &aesni_box_load_block_aes,
};

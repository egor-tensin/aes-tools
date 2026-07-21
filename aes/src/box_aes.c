/*
 * Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <stdlib.h>
#include <string.h>

static AES_StatusCode aes_box_derive_params_aes128(
    const AES_BoxKey* box_key,
    AES_BoxEncryptionRoundKeys* encryption_keys,
    AES_BoxDecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    aes128_expand_key_(box_key->aes128_key.key, &encryption_keys->aes128_encryption_keys);
    aes128_derive_decryption_keys_(
        &encryption_keys->aes128_encryption_keys, &decryption_keys->aes128_decryption_keys
    );
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_derive_params_aes192(
    const AES_BoxKey* box_key,
    AES_BoxEncryptionRoundKeys* encryption_keys,
    AES_BoxDecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    aes192_expand_key_(
        box_key->aes192_key.lo, box_key->aes192_key.hi, &encryption_keys->aes192_encryption_keys
    );
    aes192_derive_decryption_keys_(
        &encryption_keys->aes192_encryption_keys, &decryption_keys->aes192_decryption_keys
    );
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_derive_params_aes256(
    const AES_BoxKey* box_key,
    AES_BoxEncryptionRoundKeys* encryption_keys,
    AES_BoxDecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    aes256_expand_key_(
        box_key->aes256_key.lo, box_key->aes256_key.hi, &encryption_keys->aes256_encryption_keys
    );
    aes256_derive_decryption_keys_(
        &encryption_keys->aes256_encryption_keys, &decryption_keys->aes256_decryption_keys
    );
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_parse_key_aes128(
    AES_BoxKey* dest,
    const char* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes128_parse_key(&dest->aes128_key, src, err_details);
}

static AES_StatusCode aes_box_parse_key_aes192(
    AES_BoxKey* dest,
    const char* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes192_parse_key(&dest->aes192_key, src, err_details);
}

static AES_StatusCode aes_box_parse_key_aes256(
    AES_BoxKey* dest,
    const char* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes256_parse_key(&dest->aes256_key, src, err_details);
}

static AES_StatusCode aes_box_format_key_aes128(
    AES_BoxKeyString* dest,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes128_format_key(&dest->aes128, &src->aes128_key, err_details);
}

static AES_StatusCode aes_box_format_key_aes192(
    AES_BoxKeyString* dest,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes192_format_key(&dest->aes192, &src->aes192_key, err_details);
}

static AES_StatusCode aes_box_format_key_aes256(
    AES_BoxKeyString* dest,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes256_format_key(&dest->aes256, &src->aes256_key, err_details);
}

static AES_StatusCode aes_box_encrypt_block_aes128(
    const AES_Block* input,
    const AES_BoxEncryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    *output = aes128_encrypt_block_(*input, &params->aes128_encryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_decrypt_block_aes128(
    const AES_Block* input,
    const AES_BoxDecryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    *output = aes128_decrypt_block_(*input, &params->aes128_decryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_encrypt_block_aes192(
    const AES_Block* input,
    const AES_BoxEncryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    *output = aes192_encrypt_block_(*input, &params->aes192_encryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_decrypt_block_aes192(
    const AES_Block* input,
    const AES_BoxDecryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    *output = aes192_decrypt_block_(*input, &params->aes192_decryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_encrypt_block_aes256(
    const AES_Block* input,
    const AES_BoxEncryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    *output = aes256_encrypt_block_(*input, &params->aes256_encryption_keys);
    return AES_SUCCESS;
}

static AES_StatusCode aes_box_decrypt_block_aes256(
    const AES_Block* input,
    const AES_BoxDecryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_UNUSED_PARAMETER(err_details);
    *output = aes256_decrypt_block_(*input, &params->aes256_decryption_keys);
    return AES_SUCCESS;
}

AES_BoxInterface aes128_box_interface = {
    &aes_box_derive_params_aes128,
    &aes_box_parse_key_aes128,
    &aes_box_format_key_aes128,
    &aes_box_encrypt_block_aes128,
    &aes_box_decrypt_block_aes128,
};

AES_BoxInterface aes192_box_interface = {
    &aes_box_derive_params_aes192,
    &aes_box_parse_key_aes192,
    &aes_box_format_key_aes192,
    &aes_box_encrypt_block_aes192,
    &aes_box_decrypt_block_aes192,
};

AES_BoxInterface aes256_box_interface = {
    &aes_box_derive_params_aes256,
    &aes_box_parse_key_aes256,
    &aes_box_format_key_aes256,
    &aes_box_encrypt_block_aes256,
    &aes_box_decrypt_block_aes256,
};

/*
 * Copyright (c) 2026 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

static AES_StatusCode aes_parse_key_aes128(
    AES_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes128_parse_key(&dest->aes128_key, src, err_details);
}

static AES_StatusCode aes_parse_key_aes192(
    AES_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes192_parse_key(&dest->aes192_key, src, err_details);
}

static AES_StatusCode aes_parse_key_aes256(
    AES_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");

    return aes256_parse_key(&dest->aes256_key, src, err_details);
}

static AES_StatusCode aes_format_key_aes128(
    AES_KeyString* dest,
    const AES_Key* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes128_format_key(&dest->aes128, &src->aes128_key, err_details);
}

static AES_StatusCode aes_format_key_aes192(
    AES_KeyString* dest,
    const AES_Key* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes192_format_key(&dest->aes192, &src->aes192_key, err_details);
}

static AES_StatusCode aes_format_key_aes256(
    AES_KeyString* dest,
    const AES_Key* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes256_format_key(&dest->aes256, &src->aes256_key, err_details);
}

static AES_StatusCode check_expand_key_params(
    const AES_Key* key,
    AES_EncryptionRoundKeys* encryption_keys,
    AES_DecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details
) {
    if (key == NULL)
        return aes_error_null_argument(err_details, "key");
    if (encryption_keys == NULL)
        return aes_error_null_argument(err_details, "encryption_keys");
    if (decryption_keys == NULL)
        return aes_error_null_argument(err_details, "decryption_keys");
    return AES_SUCCESS;
}

static AES_StatusCode aes_expand_key_aes128(
    const AES_Key* key,
    AES_EncryptionRoundKeys* encryption_keys,
    AES_DecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status =
        check_expand_key_params(key, encryption_keys, decryption_keys, err_details);
    if (aes_is_error(status))
        return status;

    aes128_expand_key(&key->aes128_key, &encryption_keys->aes128_enc_keys);
    aes128_derive_decryption_keys(
        &encryption_keys->aes128_enc_keys, &decryption_keys->aes128_dec_keys
    );
    return status;
}

static AES_StatusCode aes_expand_key_aes192(
    const AES_Key* key,
    AES_EncryptionRoundKeys* encryption_keys,
    AES_DecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status =
        check_expand_key_params(key, encryption_keys, decryption_keys, err_details);
    if (aes_is_error(status))
        return status;

    aes192_expand_key(&key->aes192_key, &encryption_keys->aes192_enc_keys);
    aes192_derive_decryption_keys(
        &encryption_keys->aes192_enc_keys, &decryption_keys->aes192_dec_keys
    );
    return status;
}

static AES_StatusCode aes_expand_key_aes256(
    const AES_Key* key,
    AES_EncryptionRoundKeys* encryption_keys,
    AES_DecryptionRoundKeys* decryption_keys,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status =
        check_expand_key_params(key, encryption_keys, decryption_keys, err_details);
    if (aes_is_error(status))
        return status;

    aes256_expand_key(&key->aes256_key, &encryption_keys->aes256_enc_keys);
    aes256_derive_decryption_keys(
        &encryption_keys->aes256_enc_keys, &decryption_keys->aes256_dec_keys
    );
    return status;
}

static AES_StatusCode check_encrypt_params(
    const AES_Block* input,
    const AES_EncryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    if (input == NULL)
        return aes_error_null_argument(err_details, "input");
    if (params == NULL)
        return aes_error_null_argument(err_details, "params");
    if (output == NULL)
        return aes_error_null_argument(err_details, "output");
    return AES_SUCCESS;
}

static AES_StatusCode check_decrypt_params(
    const AES_Block* input,
    const AES_DecryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    if (input == NULL)
        return aes_error_null_argument(err_details, "input");
    if (params == NULL)
        return aes_error_null_argument(err_details, "params");
    if (output == NULL)
        return aes_error_null_argument(err_details, "output");
    return AES_SUCCESS;
}

static AES_StatusCode aes_encrypt_block_aes128(
    const AES_Block* input,
    const AES_EncryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = check_encrypt_params(input, params, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes128_encrypt_block(*input, &params->aes128_enc_keys);
    return status;
}

static AES_StatusCode aes_decrypt_block_aes128(
    const AES_Block* input,
    const AES_DecryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = check_decrypt_params(input, params, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes128_decrypt_block(*input, &params->aes128_dec_keys);
    return status;
}

static AES_StatusCode aes_encrypt_block_aes192(
    const AES_Block* input,
    const AES_EncryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = check_encrypt_params(input, params, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes192_encrypt_block(*input, &params->aes192_enc_keys);
    return status;
}

static AES_StatusCode aes_decrypt_block_aes192(
    const AES_Block* input,
    const AES_DecryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = check_decrypt_params(input, params, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes192_decrypt_block(*input, &params->aes192_dec_keys);
    return status;
}

static AES_StatusCode aes_encrypt_block_aes256(
    const AES_Block* input,
    const AES_EncryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = check_encrypt_params(input, params, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes256_encrypt_block(*input, &params->aes256_enc_keys);
    return status;
}

static AES_StatusCode aes_decrypt_block_aes256(
    const AES_Block* input,
    const AES_DecryptionRoundKeys* params,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = check_decrypt_params(input, params, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes256_decrypt_block(*input, &params->aes256_dec_keys);
    return status;
}

static AES_Ops aes128_ops = {
    &aes_parse_key_aes128,
    &aes_format_key_aes128,
    &aes_expand_key_aes128,
    &aes_encrypt_block_aes128,
    &aes_decrypt_block_aes128,
};

static AES_Ops aes192_ops = {
    &aes_parse_key_aes192,
    &aes_format_key_aes192,
    &aes_expand_key_aes192,
    &aes_encrypt_block_aes192,
    &aes_decrypt_block_aes192,
};

static AES_Ops aes256_ops = {
    &aes_parse_key_aes256,
    &aes_format_key_aes256,
    &aes_expand_key_aes256,
    &aes_encrypt_block_aes256,
    &aes_decrypt_block_aes256,
};

static const AES_Ops* aes_ops_list[] = {
    &aes128_ops,
    &aes192_ops,
    &aes256_ops,
};

const AES_Ops* aes_get_ops(AES_Algorithm algorithm) {
    int l = 0;
    size_t r = sizeof(aes_ops_list) / sizeof(aes_ops_list[0]) - 1;

    if ((int)algorithm < l || (size_t)algorithm > r) {
        assert(0);
        return NULL;
    }

    return aes_ops_list[algorithm];
}

AES_StatusCode aes_parse_key(
    AES_Algorithm algorithm,
    AES_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_get_ops(algorithm)->parse_key(dest, src, err_details);
}

AES_StatusCode aes_format_key(
    AES_Algorithm algorithm,
    AES_KeyString* dest,
    const AES_Key* src,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_get_ops(algorithm)->format_key(dest, src, err_details);
}

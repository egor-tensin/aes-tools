/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

static AesNI_StatusCode aesni_box_xor_state_aes(
    AesNI_State* dest,
    const AesNI_State* src,
    AesNI_ErrorDetails* err_details)
{
    dest->aes_block = aesni_xor_block128(dest->aes_block, src->aes_block);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_encrypt_aes128(
    const AesNI_State* input,
    const AesNI_EncryptionParams* params,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_raw_encrypt_block128(
        input->aes_block,
        &params->aes128_key_schedule);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_aes128(
    const AesNI_State* input,
    const AesNI_DecryptionParams* params,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_raw_decrypt_block128(
        input->aes_block,
        &params->aes128_key_schedule);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_encrypt_aes192(
    const AesNI_State* input,
    const AesNI_EncryptionParams* params,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_raw_encrypt_block192(
        input->aes_block,
        &params->aes192_key_schedule);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_aes192(
    const AesNI_State* input,
    const AesNI_DecryptionParams* params,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_raw_decrypt_block192(
        input->aes_block,
        &params->aes192_key_schedule);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_encrypt_aes256(
    const AesNI_State* input,
    const AesNI_EncryptionParams* params,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_raw_encrypt_block256(
        input->aes_block,
        &params->aes256_key_schedule);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_decrypt_aes256(
    const AesNI_State* input,
    const AesNI_DecryptionParams* params,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    output->aes_block = aesni_raw_decrypt_block256(
        input->aes_block,
        &params->aes256_key_schedule);
    return AESNI_SUCCESS;
}

typedef AesNI_StatusCode (*AesNI_BoxEncrypt)(
    const AesNI_State*,
    const AesNI_EncryptionParams* params,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details);

static AesNI_BoxEncrypt aesni_box_encrypt_algorithm[] =
{
    &aesni_box_encrypt_aes128,
    &aesni_box_encrypt_aes192,
    &aesni_box_encrypt_aes256,
};

typedef AesNI_StatusCode (*AesNI_BoxDecrypt)(
    const AesNI_State*,
    const AesNI_DecryptionParams* params,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details);

static AesNI_BoxDecrypt aesni_box_decrypt_algorithm[] =
{
    &aesni_box_decrypt_aes128,
    &aesni_box_decrypt_aes192,
    &aesni_box_decrypt_aes256,
};

typedef AesNI_StatusCode (*AesNI_BoxXorState)(
    AesNI_State*,
    const AesNI_State*,
    AesNI_ErrorDetails*);

static AesNI_BoxXorState aesni_box_xor_state[] =
{
    &aesni_box_xor_state_aes,
    &aesni_box_xor_state_aes,
    &aesni_box_xor_state_aes,
};

static AesNI_StatusCode aesni_box_init_aes128(
    AesNI_Box* box,
    const AesNI_AlgorithmParams* algorithm_params,
    AesNI_ErrorDetails* err_details)
{
    aesni_raw_expand_key_schedule128(
        algorithm_params->aes128_key,
        &box->encrypt_params.aes128_key_schedule);
    aesni_raw_invert_key_schedule128(
        &box->encrypt_params.aes128_key_schedule,
        &box->decrypt_params.aes128_key_schedule);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_init_aes192(
    AesNI_Box* box,
    const AesNI_AlgorithmParams* algorithm_params,
    AesNI_ErrorDetails* err_details)
{
    aesni_raw_expand_key_schedule192(
        algorithm_params->aes192_key.lo,
        algorithm_params->aes192_key.hi,
        &box->encrypt_params.aes192_key_schedule);
    aesni_raw_invert_key_schedule192(
        &box->encrypt_params.aes192_key_schedule,
        &box->decrypt_params.aes192_key_schedule);
    return AESNI_SUCCESS;
}

static AesNI_StatusCode aesni_box_init_aes256(
    AesNI_Box* box,
    const AesNI_AlgorithmParams* algorithm_params,
    AesNI_ErrorDetails* err_details)
{
    aesni_raw_expand_key_schedule256(
        algorithm_params->aes256_key.lo,
        algorithm_params->aes256_key.hi,
        &box->encrypt_params.aes256_key_schedule);
    aesni_raw_invert_key_schedule256(
        &box->encrypt_params.aes256_key_schedule,
        &box->decrypt_params.aes256_key_schedule);
    return AESNI_SUCCESS;
}

typedef AesNI_StatusCode (*AesNI_BoxInitializeAlgorithm)(
    AesNI_Box*,
    const AesNI_AlgorithmParams*,
    AesNI_ErrorDetails*);

static AesNI_BoxInitializeAlgorithm aesni_box_init_algorithm[] =
{
    &aesni_box_init_aes128,
    &aesni_box_init_aes192,
    &aesni_box_init_aes256,
};

AesNI_StatusCode aesni_box_init(
    AesNI_Box* box,
    AesNI_Algorithm algorithm,
    const AesNI_AlgorithmParams* algorithm_params,
    AesNI_Mode mode,
    const AesNI_State* iv,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    box->algorithm = algorithm;
    if (aesni_is_error(status = aesni_box_init_algorithm[algorithm](box, algorithm_params, err_details)))
        return status;
    box->mode = mode;
    if (iv != NULL)
        box->iv = *iv;

    return status;
}

static AesNI_StatusCode aesni_box_encrypt_ecb(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_box_encrypt_algorithm[box->algorithm](
        input,
        &box->encrypt_params,
        output,
        err_details);
}

static AesNI_StatusCode aesni_box_encrypt_cbc(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    AesNI_State xored_input = *input;
    status = aesni_box_xor_state[box->algorithm](
        &xored_input,
        &box->iv,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = aesni_box_encrypt_algorithm[box->algorithm](
        &xored_input,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *output;
    return status;
}

static AesNI_StatusCode aesni_box_encrypt_cfb(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = aesni_box_encrypt_algorithm[box->algorithm](
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = aesni_box_xor_state[box->algorithm](output, input, err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *output;
    return status;
}

static AesNI_StatusCode aesni_box_encrypt_ofb(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = aesni_box_encrypt_algorithm[box->algorithm](
        &box->iv,
        &box->encrypt_params,
        &box->iv,
        err_details);
    if (aesni_is_error(status))
        return status;

    *output = box->iv;

    status = aesni_box_xor_state[box->algorithm](output, input, err_details);
    if (aesni_is_error(status))
        return status;

    return status;
}

static AesNI_StatusCode aesni_box_encrypt_ctr(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_error_not_implemented(err_details);
}

typedef AesNI_StatusCode (*AesNI_BoxEncryptMode)(
    AesNI_Box*,
    const AesNI_State*,
    AesNI_State*,
    AesNI_ErrorDetails*);

static AesNI_BoxEncryptMode aesni_box_encrypt_mode[] =
{
    &aesni_box_encrypt_ecb,
    &aesni_box_encrypt_cbc,
    &aesni_box_encrypt_cfb,
    &aesni_box_encrypt_ofb,
    &aesni_box_encrypt_ctr,
};

AesNI_StatusCode aesni_box_encrypt(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_box_encrypt_mode[box->mode](box, input, output, err_details);
}

static AesNI_StatusCode aesni_box_decrypt_ecb(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_box_decrypt_algorithm[box->algorithm](
        input,
        &box->decrypt_params,
        output,
        err_details);
}

static AesNI_StatusCode aesni_box_decrypt_cbc(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = aesni_box_decrypt_algorithm[box->algorithm](
        input,
        &box->decrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = aesni_box_xor_state[box->algorithm](
        output,
        &box->iv,
        err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *input;
    return status;
}

static AesNI_StatusCode aesni_box_decrypt_cfb(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = aesni_box_encrypt_algorithm[box->algorithm](
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = aesni_box_xor_state[box->algorithm](
        output,
        input,
        err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *input;

    return status;
}

static AesNI_StatusCode aesni_box_decrypt_ofb(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = aesni_box_encrypt_algorithm[box->algorithm](
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *output;

    status = aesni_box_xor_state[box->algorithm](
        output,
        input,
        err_details);
    if (aesni_is_error(status))
        return status;

    return status;
}

static AesNI_StatusCode aesni_box_decrypt_ctr(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_error_not_implemented(err_details);
}

typedef AesNI_BoxEncryptMode AesNI_BoxDecryptMode;

static AesNI_BoxDecryptMode aesni_box_decrypt_mode[] =
{
    &aesni_box_decrypt_ecb,
    &aesni_box_decrypt_cbc,
    &aesni_box_decrypt_cfb,
    &aesni_box_decrypt_ofb,
    &aesni_box_decrypt_ctr,
};

AesNI_StatusCode aesni_box_decrypt(
    AesNI_Box* box,
    const AesNI_State* input,
    AesNI_State* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_box_decrypt_mode[box->mode](box, input, output, err_details);
}

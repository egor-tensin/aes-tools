/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

static const AesNI_BoxAlgorithmInterface* aesni_box_algorithms[] =
{
    &aesni_box_algorithm_aes128,
    &aesni_box_algorithm_aes192,
    &aesni_box_algorithm_aes256,
};

AesNI_StatusCode aesni_box_init(
    AesNI_Box* box,
    AesNI_BoxAlgorithm algorithm,
    const AesNI_BoxAlgorithmParams* algorithm_params,
    AesNI_BoxMode mode,
    const AesNI_BoxBlock* iv,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    box->algorithm = aesni_box_algorithms[algorithm];
    if (aesni_is_error(status = box->algorithm->derive_params(
            algorithm_params,
            &box->encrypt_params,
            &box->decrypt_params,
            err_details)))
        return status;

    box->mode = mode;
    if (iv != NULL)
        box->iv = *iv;

    return status;
}

static AesNI_StatusCode aesni_box_encrypt_block_ecb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return box->algorithm->encrypt_block(
        input,
        &box->encrypt_params,
        output,
        err_details);
}

static AesNI_StatusCode aesni_box_encrypt_block_cbc(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    AesNI_BoxBlock xored_input = *input;
    status = box->algorithm->xor_block(
        &xored_input,
        &box->iv,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm->encrypt_block(
        &xored_input,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *output;
    return status;
}

static AesNI_StatusCode aesni_box_encrypt_block_cfb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm->encrypt_block(
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm->xor_block(output, input, err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *output;
    return status;
}

static AesNI_StatusCode aesni_box_encrypt_block_ofb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm->encrypt_block(
        &box->iv,
        &box->encrypt_params,
        &box->iv,
        err_details);
    if (aesni_is_error(status))
        return status;

    *output = box->iv;

    status = box->algorithm->xor_block(output, input, err_details);
    if (aesni_is_error(status))
        return status;

    return status;
}

static AesNI_StatusCode aesni_box_encrypt_block_ctr(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm->encrypt_block(
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm->xor_block(output, input, err_details);
    if (aesni_is_error(status))
        return status;

    return box->algorithm->next_counter(&box->iv, err_details);
}

typedef AesNI_StatusCode (*AesNI_BoxEncryptBlockInMode)(
    AesNI_Box*,
    const AesNI_BoxBlock*,
    AesNI_BoxBlock*,
    AesNI_ErrorDetails*);

static AesNI_BoxEncryptBlockInMode aesni_box_encrypt_block_in_mode[] =
{
    &aesni_box_encrypt_block_ecb,
    &aesni_box_encrypt_block_cbc,
    &aesni_box_encrypt_block_cfb,
    &aesni_box_encrypt_block_ofb,
    &aesni_box_encrypt_block_ctr,
};

AesNI_StatusCode aesni_box_encrypt_block(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_box_encrypt_block_in_mode[box->mode](box, input, output, err_details);
}

static AesNI_StatusCode aesni_box_decrypt_block_ecb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return box->algorithm->decrypt_block(
        input,
        &box->decrypt_params,
        output,
        err_details);
}

static AesNI_StatusCode aesni_box_decrypt_block_cbc(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm->decrypt_block(
        input,
        &box->decrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm->xor_block(
        output,
        &box->iv,
        err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *input;
    return status;
}

static AesNI_StatusCode aesni_box_decrypt_block_cfb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm->encrypt_block(
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm->xor_block(
        output,
        input,
        err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *input;
    return status;
}

typedef AesNI_BoxEncryptBlockInMode AesNI_BoxDecryptBlockInMode;

static AesNI_BoxDecryptBlockInMode aesni_box_decrypt_block_in_mode[] =
{
    &aesni_box_decrypt_block_ecb,
    &aesni_box_decrypt_block_cbc,
    &aesni_box_decrypt_block_cfb,
    &aesni_box_encrypt_block_ofb,
    &aesni_box_encrypt_block_ctr,
};

AesNI_StatusCode aesni_box_decrypt_block(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_box_decrypt_block_in_mode[box->mode](box, input, output, err_details);
}

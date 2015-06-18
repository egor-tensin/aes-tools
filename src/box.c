/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

static const AesNI_BoxAlgorithmInterface* aesni_box_algorithm_ifaces[] =
{
    &aesni_box_aes128_iface,
    &aesni_box_aes192_iface,
    &aesni_box_aes256_iface,
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

    box->algorithm_iface = aesni_box_algorithm_ifaces[algorithm];
    if (aesni_is_error(status = box->algorithm_iface->derive_params(
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

static AesNI_StatusCode aesni_box_encrypt_ecb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return box->algorithm_iface->encrypt(
        input,
        &box->encrypt_params,
        output,
        err_details);
}

static AesNI_StatusCode aesni_box_encrypt_cbc(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    AesNI_BoxBlock xored_input = *input;
    status = box->algorithm_iface->xor_block(
        &xored_input,
        &box->iv,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm_iface->encrypt(
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
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm_iface->encrypt(
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm_iface->xor_block(output, input, err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *output;
    return status;
}

static AesNI_StatusCode aesni_box_encrypt_ofb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm_iface->encrypt(
        &box->iv,
        &box->encrypt_params,
        &box->iv,
        err_details);
    if (aesni_is_error(status))
        return status;

    *output = box->iv;

    status = box->algorithm_iface->xor_block(output, input, err_details);
    if (aesni_is_error(status))
        return status;

    return status;
}

static AesNI_StatusCode aesni_box_encrypt_ctr(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_error_not_implemented(err_details, "box encryption in CTR mode");
}

typedef AesNI_StatusCode (*AesNI_BoxEncryptMode)(
    AesNI_Box*,
    const AesNI_BoxBlock*,
    AesNI_BoxBlock*,
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
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_box_encrypt_mode[box->mode](box, input, output, err_details);
}

static AesNI_StatusCode aesni_box_decrypt_ecb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return box->algorithm_iface->decrypt(
        input,
        &box->decrypt_params,
        output,
        err_details);
}

static AesNI_StatusCode aesni_box_decrypt_cbc(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm_iface->decrypt(
        input,
        &box->decrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm_iface->xor_block(
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
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm_iface->encrypt(
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    status = box->algorithm_iface->xor_block(
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
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = box->algorithm_iface->encrypt(
        &box->iv,
        &box->encrypt_params,
        output,
        err_details);
    if (aesni_is_error(status))
        return status;

    box->iv = *output;

    status = box->algorithm_iface->xor_block(
        output,
        input,
        err_details);
    if (aesni_is_error(status))
        return status;

    return status;
}

static AesNI_StatusCode aesni_box_decrypt_ctr(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_error_not_implemented(err_details, "box decryption in CTR mode");
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
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return aesni_box_decrypt_mode[box->mode](box, input, output, err_details);
}

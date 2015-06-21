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

static const AesNI_BoxAlgorithmInterface* aesni_box_algorithms[] =
{
    &aesni_box_algorithm_aes128,
    &aesni_box_algorithm_aes192,
    &aesni_box_algorithm_aes256,
};

AesNI_StatusCode aesni_box_init(
    AesNI_Box* box,
    AesNI_Algorithm algorithm,
    const AesNI_BoxAlgorithmParams* algorithm_params,
    AesNI_Mode mode,
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
        input, &box->encrypt_params, output, err_details);
}

static AesNI_StatusCode aesni_box_encrypt_block_cbc(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;
    AesNI_BoxBlock xored_input = *input;

    if (aesni_is_error(status = box->algorithm->xor_block(
            &xored_input, &box->iv, err_details)))
        return status;

    if (aesni_is_error(status = box->algorithm->encrypt_block(
            &xored_input, &box->encrypt_params, output, err_details)))
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
    AesNI_StatusCode status = AESNI_SUCCESS;

    if (aesni_is_error(status = box->algorithm->encrypt_block(
            &box->iv, &box->encrypt_params, output, err_details)))
        return status;

    if (aesni_is_error(status = box->algorithm->xor_block(
            output, input, err_details)))
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
    AesNI_StatusCode status = AESNI_SUCCESS;

    if (aesni_is_error(status = box->algorithm->encrypt_block(
            &box->iv, &box->encrypt_params, &box->iv, err_details)))
        return status;

    *output = box->iv;

    if (aesni_is_error(status = box->algorithm->xor_block(
            output, input, err_details)))
        return status;

    return status;
}

static AesNI_StatusCode aesni_box_encrypt_block_ctr(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    if (aesni_is_error(status = box->algorithm->encrypt_block(
            &box->iv, &box->encrypt_params, output, err_details)))
        return status;

    if (aesni_is_error(status = box->algorithm->xor_block(
            output, input, err_details)))
        return status;

    if (aesni_is_error(status = box->algorithm->next_counter(
            &box->iv, err_details)))
        return status;

    return status;
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
    return aesni_box_encrypt_block_in_mode[box->mode](
        box, input, output, err_details);
}

static AesNI_StatusCode aesni_box_decrypt_block_ecb(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    return box->algorithm->decrypt_block(
        input, &box->decrypt_params, output, err_details);
}

static AesNI_StatusCode aesni_box_decrypt_block_cbc(
    AesNI_Box* box,
    const AesNI_BoxBlock* input,
    AesNI_BoxBlock* output,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    if (aesni_is_error(status = box->algorithm->decrypt_block(
            input, &box->decrypt_params, output, err_details)))
        return status;

    if (aesni_is_error(status = box->algorithm->xor_block(
            output, &box->iv, err_details)))
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
    AesNI_StatusCode status = AESNI_SUCCESS;

    if (aesni_is_error(status = box->algorithm->encrypt_block(
            &box->iv, &box->encrypt_params, output, err_details)))
        return status;

    if (aesni_is_error(status = box->algorithm->xor_block(
            output, input, err_details)))
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
    return aesni_box_decrypt_block_in_mode[box->mode](
        box, input, output, err_details);
}

static AesNI_StatusCode aesni_box_get_encrypted_buffer_size(
    AesNI_Box* box,
    size_t src_size,
    size_t* dest_size,
    size_t* padding_size,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    switch (box->mode)
    {
        case AESNI_ECB:
        case AESNI_CBC:
        {
            size_t block_size;

            if (aesni_is_error(status = box->algorithm->get_block_size(
                    &block_size, err_details)))
                return status;

            *padding_size = block_size - src_size % block_size;
            *dest_size = src_size + *padding_size;
            return status;
        }

        case AESNI_CFB:
        case AESNI_OFB:
        case AESNI_CTR:
            *dest_size = src_size;
            *padding_size = 0;
            return status;

        default:
            return aesni_error_not_implemented(
                err_details, "unsupported mode of operation");
    }
}

static AesNI_StatusCode aesni_box_encrypt_buffer_block(
    AesNI_Box* box,
    const void* src,
    void* dest,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    AesNI_BoxBlock plaintext;

    if (aesni_is_error(status = box->algorithm->load_block(
            &plaintext, src, err_details)))
        return status;

    AesNI_BoxBlock ciphertext;

    if (aesni_is_error(status = aesni_box_encrypt_block(
            box, &plaintext, &ciphertext, err_details)))
        return status;

    if (aesni_is_error(status = box->algorithm->store_block(
            dest, &ciphertext, err_details)))
        return status;

    return status;
}

static AesNI_StatusCode aesni_box_encrypt_buffer_partial_block_with_padding(
    AesNI_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t padding_size,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    size_t block_size;

    if (aesni_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    void* plaintext_buf = malloc(block_size);
    if (plaintext_buf == NULL)
        return status = aesni_error_memory_allocation(err_details);

    memcpy(plaintext_buf, src, src_size);

    if (aesni_is_error(status = aesni_fill_with_padding(
            AESNI_PADDING_PKCS7,
            (char*) plaintext_buf + src_size,
            padding_size,
            err_details)))
        goto FREE_PLAINTEXT_BUF;

    if (aesni_is_error(status = aesni_box_encrypt_buffer_block(
            box, plaintext_buf, dest, err_details)))
        goto FREE_PLAINTEXT_BUF;

FREE_PLAINTEXT_BUF:
    free(plaintext_buf);

    return status;
}

static AesNI_StatusCode aesni_box_encrypt_buffer_partial_block(
    AesNI_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    if (src_size == 0)
        return status;

    size_t block_size;

    if (aesni_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    void* plaintext_buf = malloc(block_size);
    if (plaintext_buf == NULL)
        return status = aesni_error_memory_allocation(err_details);

    memset(plaintext_buf, 0x00, block_size);
    memcpy(plaintext_buf, src, src_size);

    void* ciphertext_buf = malloc(block_size);
    if (ciphertext_buf == NULL)
    {
        status = aesni_error_memory_allocation(err_details);
        goto FREE_PLAINTEXT_BUF;
    }

    if (aesni_is_error(status = aesni_box_encrypt_buffer_block(
            box, plaintext_buf, ciphertext_buf, err_details)))
        goto FREE_CIPHERTEXT_BUF;

    memcpy(dest, ciphertext_buf, src_size);

FREE_CIPHERTEXT_BUF:
    free(ciphertext_buf);

FREE_PLAINTEXT_BUF:
    free(plaintext_buf);

    return status;
}

AesNI_StatusCode aesni_box_encrypt_buffer(
    AesNI_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AesNI_ErrorDetails* err_details)
{
    if (box == NULL)
        return aesni_error_null_argument(err_details, "box");
    if (dest_size == NULL)
        return aesni_error_null_argument(err_details, "dest_size");

    AesNI_StatusCode status = AESNI_SUCCESS;
    size_t padding_size = 0;

    if (aesni_is_error(status = aesni_box_get_encrypted_buffer_size(
            box, src_size, dest_size, &padding_size, err_details)))
        return status;

    if (dest == NULL)
        return AESNI_SUCCESS;
    if (src == NULL && src_size != 0)
        return aesni_error_null_argument(err_details, "src");

    size_t block_size;

    if (aesni_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    const size_t src_len = src_size / block_size;

    for (size_t i = 0; i < src_len; ++i, (char*) src += block_size, (char*) dest += block_size)
        if (aesni_is_error(status = aesni_box_encrypt_buffer_block(
                box, src, dest, err_details)))
            return status;

    if (padding_size == 0)
        return aesni_box_encrypt_buffer_partial_block(
            box, src, src_size % block_size, dest, err_details);
    else
        return aesni_box_encrypt_buffer_partial_block_with_padding(
            box, src, src_size % block_size, dest, padding_size, err_details);
}

static AesNI_StatusCode aesni_box_get_decrypted_buffer_size(
    AesNI_Box* box,
    size_t src_size,
    size_t* dest_size,
    size_t* max_padding_size,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    switch (box->mode)
    {
        case AESNI_ECB:
        case AESNI_CBC:
        {
            size_t block_size;

            if (aesni_is_error(status = box->algorithm->get_block_size(
                    &block_size, err_details)))
                return status;

            if (src_size == 0 || src_size % block_size != 0)
                return aesni_error_missing_padding(err_details);

            *dest_size = src_size;
            *max_padding_size = block_size;
            return status;
        }

        case AESNI_CFB:
        case AESNI_OFB:
        case AESNI_CTR:
            *dest_size = src_size;
            *max_padding_size = 0;
            return status;

        default:
            return aesni_error_not_implemented(
                err_details, "unsupported mode of operation");
    }
}

static AesNI_StatusCode aesni_box_decrypt_buffer_block(
    AesNI_Box* box,
    const void* src,
    void* dest,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    AesNI_BoxBlock ciphertext;

    if (aesni_is_error(status = box->algorithm->load_block(
            &ciphertext, src, err_details)))
        return status;

    AesNI_BoxBlock plaintext;

    if (aesni_is_error(status = aesni_box_decrypt_block(
            box, &ciphertext, &plaintext, err_details)))
        return status;

    if (aesni_is_error(status = box->algorithm->store_block(
            dest, &plaintext, err_details)))
        return status;

    return status;
}

static AesNI_StatusCode aesni_box_decrypt_buffer_partial_block(
    AesNI_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    AesNI_ErrorDetails* err_details)
{
    AesNI_StatusCode status = AESNI_SUCCESS;

    if (src_size == 0)
        return status;

    size_t block_size;

    if (aesni_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    void* ciphertext_buf = malloc(block_size);
    if (ciphertext_buf == NULL)
        return status = aesni_error_memory_allocation(err_details);

    memset(ciphertext_buf, 0x00, block_size);
    memcpy(ciphertext_buf, src, src_size);

    void* plaintext_buf = malloc(block_size);
    if (plaintext_buf == NULL)
    {
        status = aesni_error_memory_allocation(err_details);
        goto FREE_CIPHERTEXT_BUF;
    }

    if (aesni_is_error(status = aesni_box_decrypt_buffer_block(
            box, ciphertext_buf, plaintext_buf, err_details)))
        goto FREE_PLAINTEXT_BUF;

    memcpy(dest, plaintext_buf, src_size);

FREE_PLAINTEXT_BUF:
    free(plaintext_buf);

FREE_CIPHERTEXT_BUF:
    free(ciphertext_buf);

    return status;
}

AesNI_StatusCode aesni_box_decrypt_buffer(
    AesNI_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AesNI_ErrorDetails* err_details)
{
    if (box == NULL)
        return aesni_error_null_argument(err_details, "box");
    if (dest_size == NULL)
        return aesni_error_null_argument(err_details, "dest_size");

    AesNI_StatusCode status = AESNI_SUCCESS;
    size_t max_padding_size = 0;

    if (aesni_is_error(status = aesni_box_get_decrypted_buffer_size(
            box, src_size, dest_size, &max_padding_size, err_details)))
        return status;

    if (dest == NULL)
        return AESNI_SUCCESS;
    if (src == NULL)
        return aesni_error_null_argument(err_details, "src");

    size_t block_size;

    if (aesni_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    const size_t src_len = src_size / block_size;

    for (size_t i = 0; i < src_len; ++i, (char*) src += block_size, (char*) dest += block_size)
        if (aesni_is_error(status = aesni_box_decrypt_buffer_block(
                box, src, dest, err_details)))
            return status;

    if (max_padding_size == 0)
    {
        return aesni_box_decrypt_buffer_partial_block(
            box, src, src_size % block_size, dest, err_details);
    }
    else
    {
        size_t padding_size;

        if (aesni_is_error(status = aesni_extract_padding_size(
                AESNI_PADDING_PKCS7,
                (char*) dest - block_size,
                block_size,
                &padding_size,
                err_details)))
            return status;

        *dest_size -= padding_size;
        return status;
    }
}

/*
 * Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <stdlib.h>
#include <string.h>

static const AES_BoxAlgorithmInterface* aes_box_algorithms[] =
{
    &aes_box_algorithm_aes128,
    &aes_box_algorithm_aes192,
    &aes_box_algorithm_aes256,
};

AES_StatusCode aes_box_init(
    AES_Box* box,
    AES_Algorithm algorithm,
    const AES_BoxKey* box_key,
    AES_Mode mode,
    const AES_BoxBlock* iv,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    box->algorithm = aes_box_algorithms[algorithm];

    if (aes_is_error(status = box->algorithm->calc_round_keys(
            box_key,
            &box->encryption_keys,
            &box->decryption_keys,
            err_details)))
        return status;

    box->mode = mode;
    if (iv != NULL)
        box->iv = *iv;

    return status;
}

static AES_StatusCode aes_box_encrypt_block_ecb(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    return box->algorithm->encrypt_block(
        input, &box->encryption_keys, output, err_details);
}

static AES_StatusCode aes_box_encrypt_block_cbc(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;
    AES_BoxBlock xored_input = *input;

    if (aes_is_error(status = box->algorithm->xor_block(
            &xored_input, &box->iv, err_details)))
        return status;

    if (aes_is_error(status = box->algorithm->encrypt_block(
            &xored_input, &box->encryption_keys, output, err_details)))
        return status;

    box->iv = *output;
    return status;
}

static AES_StatusCode aes_box_encrypt_block_cfb(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    if (aes_is_error(status = box->algorithm->encrypt_block(
            &box->iv, &box->encryption_keys, output, err_details)))
        return status;

    if (aes_is_error(status = box->algorithm->xor_block(
            output, input, err_details)))
        return status;

    box->iv = *output;
    return status;
}

static AES_StatusCode aes_box_encrypt_block_ofb(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    if (aes_is_error(status = box->algorithm->encrypt_block(
            &box->iv, &box->encryption_keys, &box->iv, err_details)))
        return status;

    *output = box->iv;

    if (aes_is_error(status = box->algorithm->xor_block(
            output, input, err_details)))
        return status;

    return status;
}

static AES_StatusCode aes_box_encrypt_block_ctr(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    if (aes_is_error(status = box->algorithm->encrypt_block(
            &box->iv, &box->encryption_keys, output, err_details)))
        return status;

    if (aes_is_error(status = box->algorithm->xor_block(
            output, input, err_details)))
        return status;

    if (aes_is_error(status = box->algorithm->inc_block(
            &box->iv, err_details)))
        return status;

    return status;
}

typedef AES_StatusCode (*AES_BoxEncryptBlockInMode)(
    AES_Box*,
    const AES_BoxBlock*,
    AES_BoxBlock*,
    AES_ErrorDetails*);

static AES_BoxEncryptBlockInMode aes_box_encrypt_block_in_mode[] =
{
    &aes_box_encrypt_block_ecb,
    &aes_box_encrypt_block_cbc,
    &aes_box_encrypt_block_cfb,
    &aes_box_encrypt_block_ofb,
    &aes_box_encrypt_block_ctr,
};

AES_StatusCode aes_box_encrypt_block(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    return aes_box_encrypt_block_in_mode[box->mode](
        box, input, output, err_details);
}

static AES_StatusCode aes_box_decrypt_block_ecb(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    return box->algorithm->decrypt_block(
        input, &box->decryption_keys, output, err_details);
}

static AES_StatusCode aes_box_decrypt_block_cbc(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    if (aes_is_error(status = box->algorithm->decrypt_block(
            input, &box->decryption_keys, output, err_details)))
        return status;

    if (aes_is_error(status = box->algorithm->xor_block(
            output, &box->iv, err_details)))
        return status;

    box->iv = *input;
    return status;
}

static AES_StatusCode aes_box_decrypt_block_cfb(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    if (aes_is_error(status = box->algorithm->encrypt_block(
            &box->iv, &box->encryption_keys, output, err_details)))
        return status;

    if (aes_is_error(status = box->algorithm->xor_block(
            output, input, err_details)))
        return status;

    box->iv = *input;
    return status;
}

typedef AES_BoxEncryptBlockInMode AES_BoxDecryptBlockInMode;

static AES_BoxDecryptBlockInMode aes_box_decrypt_block_in_mode[] =
{
    &aes_box_decrypt_block_ecb,
    &aes_box_decrypt_block_cbc,
    &aes_box_decrypt_block_cfb,
    &aes_box_encrypt_block_ofb,
    &aes_box_encrypt_block_ctr,
};

AES_StatusCode aes_box_decrypt_block(
    AES_Box* box,
    const AES_BoxBlock* input,
    AES_BoxBlock* output,
    AES_ErrorDetails* err_details)
{
    return aes_box_decrypt_block_in_mode[box->mode](
        box, input, output, err_details);
}

static AES_StatusCode aes_box_get_encrypted_buffer_size(
    AES_Box* box,
    size_t src_size,
    size_t* dest_size,
    size_t* padding_size,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    switch (box->mode)
    {
        case AES_ECB:
        case AES_CBC:
        {
            size_t block_size;

            if (aes_is_error(status = box->algorithm->get_block_size(
                    &block_size, err_details)))
                return status;

            *padding_size = block_size - src_size % block_size;
            *dest_size = src_size + *padding_size;
            return status;
        }

        case AES_CFB:
        case AES_OFB:
        case AES_CTR:
            *dest_size = src_size;
            *padding_size = 0;
            return status;

        default:
            return aes_error_not_implemented(
                err_details, "unsupported mode of operation");
    }
}

static AES_StatusCode aes_box_encrypt_buffer_block(
    AES_Box* box,
    const void* src,
    void* dest,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    AES_BoxBlock plaintext;

    if (aes_is_error(status = box->algorithm->load_block(
            &plaintext, src, err_details)))
        return status;

    AES_BoxBlock ciphertext;

    if (aes_is_error(status = aes_box_encrypt_block(
            box, &plaintext, &ciphertext, err_details)))
        return status;

    if (aes_is_error(status = box->algorithm->store_block(
            dest, &ciphertext, err_details)))
        return status;

    return status;
}

static AES_StatusCode aes_box_encrypt_buffer_partial_block_with_padding(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t padding_size,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    size_t block_size;

    if (aes_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    void* plaintext_buf = malloc(block_size);

    if (plaintext_buf == NULL)
        return status = aes_error_memory_allocation(err_details);

    memcpy(plaintext_buf, src, src_size);

    if (aes_is_error(status = aes_fill_with_padding(
            AES_PADDING_PKCS7,
            (char*) plaintext_buf + src_size,
            padding_size,
            err_details)))
        goto FREE_PLAINTEXT_BUF;

    if (aes_is_error(status = aes_box_encrypt_buffer_block(
            box, plaintext_buf, dest, err_details)))
        goto FREE_PLAINTEXT_BUF;

FREE_PLAINTEXT_BUF:
    free(plaintext_buf);

    return status;
}

static AES_StatusCode aes_box_encrypt_buffer_partial_block(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    if (src_size == 0)
        return status;

    size_t block_size;

    if (aes_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    void* plaintext_buf = malloc(block_size);

    if (plaintext_buf == NULL)
        return status = aes_error_memory_allocation(err_details);

    memset(plaintext_buf, 0x00, block_size);
    memcpy(plaintext_buf, src, src_size);

    void* ciphertext_buf = malloc(block_size);

    if (ciphertext_buf == NULL)
    {
        status = aes_error_memory_allocation(err_details);
        goto FREE_PLAINTEXT_BUF;
    }

    if (aes_is_error(status = aes_box_encrypt_buffer_block(
            box, plaintext_buf, ciphertext_buf, err_details)))
        goto FREE_CIPHERTEXT_BUF;

    memcpy(dest, ciphertext_buf, src_size);

FREE_CIPHERTEXT_BUF:
    free(ciphertext_buf);

FREE_PLAINTEXT_BUF:
    free(plaintext_buf);

    return status;
}

AES_StatusCode aes_box_encrypt_buffer(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    if (box == NULL)
        return aes_error_null_argument(err_details, "box");
    if (dest_size == NULL)
        return aes_error_null_argument(err_details, "dest_size");

    size_t padding_size = 0;

    if (aes_is_error(status = aes_box_get_encrypted_buffer_size(
            box, src_size, dest_size, &padding_size, err_details)))
        return status;

    if (dest == NULL)
        return AES_SUCCESS;
    if (src == NULL && src_size != 0)
        return aes_error_null_argument(err_details, "src");

    size_t block_size;

    if (aes_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    const size_t src_len = src_size / block_size;

    for (size_t i = 0; i < src_len; ++i)
    {
        if (aes_is_error(status = aes_box_encrypt_buffer_block(
                box, src, dest, err_details)))
            return status;

        src = (char*) src + block_size;
        dest = (char*) dest + block_size;
    }

    if (padding_size == 0)
        return aes_box_encrypt_buffer_partial_block(
            box, src, src_size % block_size, dest, err_details);
    else
        return aes_box_encrypt_buffer_partial_block_with_padding(
            box, src, src_size % block_size, dest, padding_size, err_details);
}

static AES_StatusCode aes_box_get_decrypted_buffer_size(
    AES_Box* box,
    size_t src_size,
    size_t* dest_size,
    size_t* max_padding_size,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    switch (box->mode)
    {
        case AES_ECB:
        case AES_CBC:
        {
            size_t block_size;

            if (aes_is_error(status = box->algorithm->get_block_size(
                    &block_size, err_details)))
                return status;

            if (src_size == 0 || src_size % block_size != 0)
                return aes_error_missing_padding(err_details);

            *dest_size = src_size;
            *max_padding_size = block_size;
            return status;
        }

        case AES_CFB:
        case AES_OFB:
        case AES_CTR:
            *dest_size = src_size;
            *max_padding_size = 0;
            return status;

        default:
            return aes_error_not_implemented(
                err_details, "unsupported mode of operation");
    }
}

static AES_StatusCode aes_box_decrypt_buffer_block(
    AES_Box* box,
    const void* src,
    void* dest,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    AES_BoxBlock ciphertext;

    if (aes_is_error(status = box->algorithm->load_block(
            &ciphertext, src, err_details)))
        return status;

    AES_BoxBlock plaintext;

    if (aes_is_error(status = aes_box_decrypt_block(
            box, &ciphertext, &plaintext, err_details)))
        return status;

    if (aes_is_error(status = box->algorithm->store_block(
            dest, &plaintext, err_details)))
        return status;

    return status;
}

static AES_StatusCode aes_box_decrypt_buffer_partial_block(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    AES_ErrorDetails* err_details)
{
    AES_StatusCode status = AES_SUCCESS;

    if (src_size == 0)
        return status;

    size_t block_size;

    if (aes_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    void* ciphertext_buf = malloc(block_size);

    if (ciphertext_buf == NULL)
        return status = aes_error_memory_allocation(err_details);

    memset(ciphertext_buf, 0x00, block_size);
    memcpy(ciphertext_buf, src, src_size);

    void* plaintext_buf = malloc(block_size);

    if (plaintext_buf == NULL)
    {
        status = aes_error_memory_allocation(err_details);
        goto FREE_CIPHERTEXT_BUF;
    }

    if (aes_is_error(status = aes_box_decrypt_buffer_block(
            box, ciphertext_buf, plaintext_buf, err_details)))
        goto FREE_PLAINTEXT_BUF;

    memcpy(dest, plaintext_buf, src_size);

FREE_PLAINTEXT_BUF:
    free(plaintext_buf);

FREE_CIPHERTEXT_BUF:
    free(ciphertext_buf);

    return status;
}

AES_StatusCode aes_box_decrypt_buffer(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AES_ErrorDetails* err_details)
{
    if (box == NULL)
        return aes_error_null_argument(err_details, "box");
    if (dest_size == NULL)
        return aes_error_null_argument(err_details, "dest_size");

    AES_StatusCode status = AES_SUCCESS;
    size_t max_padding_size = 0;

    if (aes_is_error(status = aes_box_get_decrypted_buffer_size(
            box, src_size, dest_size, &max_padding_size, err_details)))
        return status;

    if (dest == NULL)
        return AES_SUCCESS;
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    size_t block_size;

    if (aes_is_error(status = box->algorithm->get_block_size(
            &block_size, err_details)))
        return status;

    const size_t src_len = src_size / block_size;

    for (size_t i = 0; i < src_len; ++i)
    {
        if (aes_is_error(status = aes_box_decrypt_buffer_block(
                box, src, dest, err_details)))
            return status;

        src = (char*) src + block_size;
        dest = (char*) dest + block_size;
    }

    if (max_padding_size == 0)
    {
        return aes_box_decrypt_buffer_partial_block(
            box, src, src_size % block_size, dest, err_details);
    }
    else
    {
        size_t padding_size;

        if (aes_is_error(status = aes_extract_padding_size(
                AES_PADDING_PKCS7,
                (char*) dest - block_size,
                block_size,
                &padding_size,
                err_details)))
            return status;

        *dest_size -= padding_size;
        return status;
    }
}

AES_StatusCode aes_box_parse_block(
    AES_BoxBlock* dest,
    AES_Algorithm algorithm,
    const char* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_box_algorithms[algorithm]->parse_block(
        dest, src, err_details);
}

AES_StatusCode aes_box_parse_key(
    AES_BoxKey* dest,
    AES_Algorithm algorithm,
    const char* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_box_algorithms[algorithm]->parse_key(
        dest, src, err_details);
}

AES_StatusCode aes_box_format_block(
    AES_BoxBlockString* dest,
    AES_Algorithm algorithm,
    const AES_BoxBlock* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_box_algorithms[algorithm]->format_block(
        dest, src, err_details);
}

AES_StatusCode aes_box_format_key(
    AES_BoxKeyString* dest,
    AES_Algorithm algorithm,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details)
{
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    return aes_box_algorithms[algorithm]->format_key(
        dest, src, err_details);
}

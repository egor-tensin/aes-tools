/*
 * Copyright (c) 2015 Egor Tensin <egor@tensin.name>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <stdlib.h>
#include <string.h>

AES_StatusCode aes_box_init(
    AES_Box* box,
    AES_Algorithm algorithm,
    const AES_Key* box_key,
    AES_Mode mode,
    const AES_Block* iv,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    box->algorithm = algorithm;
    box->mode = mode;

    if (!iv && aes_mode_requires_init_vector(mode))
        return aes_error_mode_requires_init_vector(err_details);
    if (iv)
        box->iv = *iv;

    box->ops = aes_get_ops(algorithm);

    status =
        box->ops->expand_key(box_key, &box->encryption_keys, &box->decryption_keys, err_details);
    if (aes_is_error(status))
        return status;

    return status;
}

static AES_StatusCode aes_box_encrypt_block_ecb(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    return box->ops->encrypt_block(input, &box->encryption_keys, output, err_details);
}

static AES_StatusCode aes_box_encrypt_block_cbc(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;
    AES_Block xored_input = aes_xor_blocks(*input, box->iv);

    status = box->ops->encrypt_block(&xored_input, &box->encryption_keys, output, err_details);
    if (aes_is_error(status))
        return status;

    box->iv = *output;
    return status;
}

static AES_StatusCode aes_box_encrypt_block_cfb(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    status = box->ops->encrypt_block(&box->iv, &box->encryption_keys, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes_xor_blocks(*output, *input);
    box->iv = *output;

    return status;
}

static AES_StatusCode aes_box_encrypt_block_ofb(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    status = box->ops->encrypt_block(&box->iv, &box->encryption_keys, &box->iv, err_details);
    if (aes_is_error(status))
        return status;

    *output = box->iv;
    *output = aes_xor_blocks(*output, *input);

    return status;
}

static AES_StatusCode aes_box_encrypt_block_ctr(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    status = box->ops->encrypt_block(&box->iv, &box->encryption_keys, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes_xor_blocks(*output, *input);
    box->iv = aes_inc_block(box->iv);

    return status;
}

typedef AES_StatusCode (*AES_BoxEncryptBlockInMode)(
    AES_Box*,
    const AES_Block*,
    AES_Block*,
    AES_ErrorDetails*
);

static AES_BoxEncryptBlockInMode aes_box_encrypt_block_in_mode[] = {
    &aes_box_encrypt_block_ecb,
    &aes_box_encrypt_block_cbc,
    &aes_box_encrypt_block_cfb,
    &aes_box_encrypt_block_ofb,
    &aes_box_encrypt_block_ctr,
};

AES_StatusCode aes_box_encrypt_block(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    if (box == NULL)
        return aes_error_null_argument(err_details, "box");
    if (input == NULL)
        return aes_error_null_argument(err_details, "input");
    if (output == NULL)
        return aes_error_null_argument(err_details, "output");

    return aes_box_encrypt_block_in_mode[box->mode](box, input, output, err_details);
}

static AES_StatusCode aes_box_decrypt_block_ecb(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    return box->ops->decrypt_block(input, &box->decryption_keys, output, err_details);
}

static AES_StatusCode aes_box_decrypt_block_cbc(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    status = box->ops->decrypt_block(input, &box->decryption_keys, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes_xor_blocks(*output, box->iv);
    box->iv = *input;

    return status;
}

static AES_StatusCode aes_box_decrypt_block_cfb(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    status = box->ops->encrypt_block(&box->iv, &box->encryption_keys, output, err_details);
    if (aes_is_error(status))
        return status;

    *output = aes_xor_blocks(*output, *input);
    box->iv = *input;

    return status;
}

typedef AES_BoxEncryptBlockInMode AES_BoxDecryptBlockInMode;

static AES_BoxDecryptBlockInMode aes_box_decrypt_block_in_mode[] = {
    &aes_box_decrypt_block_ecb,
    &aes_box_decrypt_block_cbc,
    &aes_box_decrypt_block_cfb,
    &aes_box_encrypt_block_ofb,
    &aes_box_encrypt_block_ctr,
};

AES_StatusCode aes_box_decrypt_block(
    AES_Box* box,
    const AES_Block* input,
    AES_Block* output,
    AES_ErrorDetails* err_details
) {
    return aes_box_decrypt_block_in_mode[box->mode](box, input, output, err_details);
}

static AES_StatusCode aes_box_get_encrypted_buffer_size(
    AES_Box* box,
    size_t src_size,
    size_t* dest_size,
    size_t* padding_size,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    switch (box->mode) {
        case AES_ECB:
        case AES_CBC: {
            size_t block_size = sizeof(AES_Block);
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
            return aes_error_not_implemented(err_details, "unsupported mode of operation");
    }
}

static AES_StatusCode aes_box_encrypt_buffer_block(
    AES_Box* box,
    const void* src,
    void* dest,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;
    AES_Block plaintext = aes_load_block(src);
    AES_Block ciphertext;

    status = aes_box_encrypt_block(box, &plaintext, &ciphertext, err_details);
    if (aes_is_error(status))
        return status;

    aes_store_block(dest, ciphertext);
    return status;
}

static AES_StatusCode aes_box_encrypt_buffer_partial_block_with_padding(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t padding_size,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    size_t block_size = sizeof(AES_Block);
    void* plaintext_buf = malloc(block_size);

    if (plaintext_buf == NULL)
        return status = aes_error_memory_allocation(err_details);

    memcpy(plaintext_buf, src, src_size);

    status = aes_fill_with_padding(
        AES_PADDING_PKCS7, (char*)plaintext_buf + src_size, padding_size, err_details
    );
    if (aes_is_error(status))
        goto FREE_PLAINTEXT_BUF;

    status = aes_box_encrypt_buffer_block(box, plaintext_buf, dest, err_details);
    if (aes_is_error(status))
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
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    if (src_size == 0)
        return status;

    size_t block_size = sizeof(AES_Block);
    void* plaintext_buf = malloc(block_size);

    if (plaintext_buf == NULL)
        return status = aes_error_memory_allocation(err_details);

    memset(plaintext_buf, 0x00, block_size);
    memcpy(plaintext_buf, src, src_size);

    void* ciphertext_buf = malloc(block_size);

    if (ciphertext_buf == NULL) {
        status = aes_error_memory_allocation(err_details);
        goto FREE_PLAINTEXT_BUF;
    }

    status = aes_box_encrypt_buffer_block(box, plaintext_buf, ciphertext_buf, err_details);
    if (aes_is_error(status))
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
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    if (box == NULL)
        return aes_error_null_argument(err_details, "box");
    if (dest_size == NULL)
        return aes_error_null_argument(err_details, "dest_size");

    size_t padding_size = 0;

    status =
        aes_box_get_encrypted_buffer_size(box, src_size, dest_size, &padding_size, err_details);
    if (aes_is_error(status))
        return status;

    if (dest == NULL)
        return AES_SUCCESS;
    if (src == NULL && src_size != 0)
        return aes_error_null_argument(err_details, "src");

    size_t block_size = sizeof(AES_Block);
    const size_t src_len = src_size / block_size;

    for (size_t i = 0; i < src_len; ++i) {
        status = aes_box_encrypt_buffer_block(box, src, dest, err_details);
        if (aes_is_error(status))
            return status;

        src = (char*)src + block_size;
        dest = (char*)dest + block_size;
    }

    if (padding_size == 0)
        return aes_box_encrypt_buffer_partial_block(
            box, src, src_size % block_size, dest, err_details
        );
    else
        return aes_box_encrypt_buffer_partial_block_with_padding(
            box, src, src_size % block_size, dest, padding_size, err_details
        );
}

static AES_StatusCode aes_box_get_decrypted_buffer_size(
    AES_Box* box,
    size_t src_size,
    size_t* dest_size,
    size_t* max_padding_size,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    switch (box->mode) {
        case AES_ECB:
        case AES_CBC: {
            size_t block_size = sizeof(AES_Block);

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
            return aes_error_not_implemented(err_details, "unsupported mode of operation");
    }
}

static AES_StatusCode aes_box_decrypt_buffer_block(
    AES_Box* box,
    const void* src,
    void* dest,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;
    AES_Block ciphertext = aes_load_block(src);
    AES_Block plaintext;

    status = aes_box_decrypt_block(box, &ciphertext, &plaintext, err_details);
    if (aes_is_error(status))
        return status;

    aes_store_block(dest, plaintext);
    return status;
}

static AES_StatusCode aes_box_decrypt_buffer_partial_block(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    AES_ErrorDetails* err_details
) {
    AES_StatusCode status = AES_SUCCESS;

    if (src_size == 0)
        return status;

    size_t block_size = sizeof(AES_Block);
    void* ciphertext_buf = malloc(block_size);

    if (ciphertext_buf == NULL)
        return status = aes_error_memory_allocation(err_details);

    memset(ciphertext_buf, 0x00, block_size);
    memcpy(ciphertext_buf, src, src_size);

    void* plaintext_buf = malloc(block_size);

    if (plaintext_buf == NULL) {
        status = aes_error_memory_allocation(err_details);
        goto FREE_CIPHERTEXT_BUF;
    }

    status = aes_box_decrypt_buffer_block(box, ciphertext_buf, plaintext_buf, err_details);
    if (aes_is_error(status))
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
    AES_ErrorDetails* err_details
) {
    if (box == NULL)
        return aes_error_null_argument(err_details, "box");
    if (dest_size == NULL)
        return aes_error_null_argument(err_details, "dest_size");

    AES_StatusCode status = AES_SUCCESS;
    size_t max_padding_size = 0;

    status =
        aes_box_get_decrypted_buffer_size(box, src_size, dest_size, &max_padding_size, err_details);
    if (aes_is_error(status))
        return status;

    if (dest == NULL)
        return AES_SUCCESS;
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    size_t block_size = sizeof(AES_Block);
    const size_t src_len = src_size / block_size;

    for (size_t i = 0; i < src_len; ++i) {
        status = aes_box_decrypt_buffer_block(box, src, dest, err_details);
        if (aes_is_error(status))
            return status;

        src = (char*)src + block_size;
        dest = (char*)dest + block_size;
    }

    if (max_padding_size == 0) {
        return aes_box_decrypt_buffer_partial_block(
            box, src, src_size % block_size, dest, err_details
        );
    } else {
        size_t padding_size;

        status = aes_extract_padding_size(
            AES_PADDING_PKCS7, (char*)dest - block_size, block_size, &padding_size, err_details
        );
        if (aes_is_error(status))
            return status;

        *dest_size -= padding_size;
        return status;
    }
}

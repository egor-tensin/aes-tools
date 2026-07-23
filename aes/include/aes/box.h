/*
 * Copyright (c) 2015 Egor Tensin <egor@tensin.name>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#pragma once

#include "algorithm.h"
#include "block.h"
#include "error.h"
#include "mode.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    AES_Algorithm algorithm;
    AES_Mode mode;
    AES_Block iv;
    AES_EncryptionRoundKeys encryption_keys;
    AES_DecryptionRoundKeys decryption_keys;
    const AES_Ops* ops;
} AES_Box;

AES_StatusCode aes_box_init(
    AES_Box* box,
    AES_Algorithm algorithm,
    const AES_Key* box_key,
    AES_Mode mode,
    const AES_Block* iv,
    AES_ErrorDetails* err_details
);

AES_StatusCode aes_box_encrypt_block(
    AES_Box* box,
    const AES_Block* plaintext,
    AES_Block* ciphertext,
    AES_ErrorDetails* err_details
);

AES_StatusCode aes_box_decrypt_block(
    AES_Box* box,
    const AES_Block* ciphertext,
    AES_Block* plaintext,
    AES_ErrorDetails* err_details
);

AES_StatusCode aes_box_encrypt_buffer(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AES_ErrorDetails* err_details
);

AES_StatusCode aes_box_decrypt_buffer(
    AES_Box* box,
    const void* src,
    size_t src_size,
    void* dest,
    size_t* dest_size,
    AES_ErrorDetails* err_details
);

#ifdef __cplusplus
}
#endif

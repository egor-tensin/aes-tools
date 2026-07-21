// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "aes.h"
#include "algorithm.h"
#include "error.h"
#include "mode.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
    AES128_Key aes128_key;
    AES192_Key aes192_key;
    AES256_Key aes256_key;
} AES_BoxKey;

typedef union {
    AES128_RoundKeys aes128_encryption_keys;
    AES192_RoundKeys aes192_encryption_keys;
    AES256_RoundKeys aes256_encryption_keys;
} AES_BoxEncryptionRoundKeys;

typedef union {
    AES128_RoundKeys aes128_decryption_keys;
    AES192_RoundKeys aes192_decryption_keys;
    AES256_RoundKeys aes256_decryption_keys;
} AES_BoxDecryptionRoundKeys;

typedef union {
    AES128_KeyString aes128;
    AES192_KeyString aes192;
    AES256_KeyString aes256;
} AES_BoxKeyString;

typedef AES_StatusCode (*AES_BoxCalculateRoundKeys)(
    const AES_BoxKey* params,
    AES_BoxEncryptionRoundKeys*,
    AES_BoxDecryptionRoundKeys*,
    AES_ErrorDetails* err_details
);

typedef AES_StatusCode (*AES_BoxParseKey)(
    AES_BoxKey* dest,
    const char* src,
    AES_ErrorDetails* err_details
);

typedef AES_StatusCode (*AES_BoxFormatKey)(
    AES_BoxKeyString* dest,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details
);

typedef AES_StatusCode (*AES_BoxEncryptBlock)(
    const AES_Block* plaintext,
    const AES_BoxEncryptionRoundKeys* params,
    AES_Block* ciphertext,
    AES_ErrorDetails* err_details
);

typedef AES_StatusCode (*AES_BoxDecryptBlock)(
    const AES_Block* ciphertext,
    const AES_BoxDecryptionRoundKeys* params,
    AES_Block* plaintext,
    AES_ErrorDetails* err_details
);

typedef struct {
    AES_BoxCalculateRoundKeys calc_round_keys;
    AES_BoxParseKey parse_key;
    AES_BoxFormatKey format_key;
    AES_BoxEncryptBlock encrypt_block;
    AES_BoxDecryptBlock decrypt_block;
} AES_BoxOps;

typedef struct {
    AES_Algorithm algorithm;
    AES_Mode mode;
    AES_Block iv;
    AES_BoxEncryptionRoundKeys encryption_keys;
    AES_BoxDecryptionRoundKeys decryption_keys;
    const AES_BoxOps* ops;
} AES_Box;

#ifdef __cplusplus
}
#endif

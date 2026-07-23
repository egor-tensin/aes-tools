/*
 * Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AES_AES128,
    AES_AES192,
    AES_AES256,
} AES_Algorithm;

typedef union {
    AES128_Key aes128_key;
    AES192_Key aes192_key;
    AES256_Key aes256_key;
} AES_Key;

typedef union {
    AES128_KeyString aes128;
    AES192_KeyString aes192;
    AES256_KeyString aes256;
} AES_KeyString;

typedef union {
    AES128_RoundKeys aes128_enc_keys;
    AES192_RoundKeys aes192_enc_keys;
    AES256_RoundKeys aes256_enc_keys;
} AES_EncryptionRoundKeys;

typedef union {
    AES128_RoundKeys aes128_dec_keys;
    AES192_RoundKeys aes192_dec_keys;
    AES256_RoundKeys aes256_dec_keys;
} AES_DecryptionRoundKeys;

typedef AES_StatusCode (*AES_ParseKey)(
    AES_Key* dest,
    const char* src,
    AES_ErrorDetails* err_details
);

typedef AES_StatusCode (*AES_FormatKey)(
    AES_KeyString* dest,
    const AES_Key* src,
    AES_ErrorDetails* err_details
);

typedef AES_StatusCode (*AES_ExpandKey)(
    const AES_Key* params,
    AES_EncryptionRoundKeys*,
    AES_DecryptionRoundKeys*,
    AES_ErrorDetails* err_details
);

typedef AES_StatusCode (*AES_EncryptBlock)(
    const AES_Block* plaintext,
    const AES_EncryptionRoundKeys* params,
    AES_Block* ciphertext,
    AES_ErrorDetails* err_details
);

typedef AES_StatusCode (*AES_DecryptBlock)(
    const AES_Block* ciphertext,
    const AES_DecryptionRoundKeys* params,
    AES_Block* plaintext,
    AES_ErrorDetails* err_details
);

typedef struct {
    AES_ParseKey parse_key;
    AES_FormatKey format_key;
    AES_ExpandKey expand_key;
    AES_EncryptBlock encrypt_block;
    AES_DecryptBlock decrypt_block;
} AES_Ops;

const AES_Ops* aes_get_ops(AES_Algorithm);

AES_StatusCode aes_parse_key(AES_Algorithm, AES_Key*, const char*, AES_ErrorDetails*);
AES_StatusCode aes_format_key(AES_Algorithm, AES_KeyString*, const AES_Key*, AES_ErrorDetails*);

#ifdef __cplusplus
}
#endif

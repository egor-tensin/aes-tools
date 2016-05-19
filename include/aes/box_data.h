/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "aes.h"
#include "error.h"
#include "mode.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef union
{
    AES_AES128_Key aes128_key;
    AES_AES192_Key aes192_key;
    AES_AES256_Key aes256_key;
}
AES_BoxKey;

typedef union
{
    AES_AES128_RoundKeys aes128_encryption_keys;
    AES_AES192_RoundKeys aes192_encryption_keys;
    AES_AES256_RoundKeys aes256_encryption_keys;
}
AES_BoxEncryptionRoundKeys;

typedef union
{
    AES_AES128_RoundKeys aes128_decryption_keys;
    AES_AES192_RoundKeys aes192_decryption_keys;
    AES_AES256_RoundKeys aes256_decryption_keys;
}
AES_BoxDecryptionRoundKeys;

typedef union
{
    AES_AES128_KeyString aes128;
    AES_AES192_KeyString aes192;
    AES_AES256_KeyString aes256;
}
AES_BoxKeyString;

typedef union
{
    AES_AES_Block aes_block;
}
AES_BoxBlock;

typedef union
{
    AES_AES_BlockString aes;
}
AES_BoxBlockString;

typedef AES_StatusCode (*AES_BoxCalculateRoundKeys)(
    const AES_BoxKey* params,
    AES_BoxEncryptionRoundKeys*,
    AES_BoxDecryptionRoundKeys*,
    AES_ErrorDetails* err_details);

typedef AES_StatusCode (*AES_BoxParseBlock)(
    AES_BoxBlock* dest,
    const char* src,
    AES_ErrorDetails* err_details);

typedef AES_StatusCode (*AES_BoxParseKey)(
    AES_BoxKey* dest,
    const char* src,
    AES_ErrorDetails* err_details);

typedef AES_StatusCode (*AES_BoxFormatBlock)(
    AES_BoxBlockString* dest,
    const AES_BoxBlock* src,
    AES_ErrorDetails* err_details);

typedef AES_StatusCode (*AES_BoxFormatKey)(
    AES_BoxKeyString* dest,
    const AES_BoxKey* src,
    AES_ErrorDetails* err_details);

typedef AES_StatusCode (*AES_BoxEncryptBlock)(
    const AES_BoxBlock* plaintext,
    const AES_BoxEncryptionRoundKeys* params,
    AES_BoxBlock* ciphertext,
    AES_ErrorDetails* err_details);

typedef AES_StatusCode (*AES_BoxDecryptBlock)(
    const AES_BoxBlock* ciphertext,
    const AES_BoxDecryptionRoundKeys* params,
    AES_BoxBlock* plaintext,
    AES_ErrorDetails* err_details);

typedef AES_StatusCode (*AES_BoxXorBlock)(
    AES_BoxBlock*,
    const AES_BoxBlock*,
    AES_ErrorDetails*);

typedef AES_StatusCode (*AES_BoxIncBlock)(
    AES_BoxBlock*,
    AES_ErrorDetails*);

typedef AES_StatusCode (*AES_BoxGetBlockSize)(
    size_t*,
    AES_ErrorDetails*);

typedef AES_StatusCode (*AES_BoxStoreBlock)(
    void*,
    const AES_BoxBlock*,
    AES_ErrorDetails*);

typedef AES_StatusCode (*AES_BoxLoadBlock)(
    AES_BoxBlock*,
    const void*,
    AES_ErrorDetails*);

typedef struct
{
    AES_BoxCalculateRoundKeys calc_round_keys;
    AES_BoxParseBlock parse_block;
    AES_BoxParseKey parse_key;
    AES_BoxFormatBlock format_block;
    AES_BoxFormatKey format_key;
    AES_BoxEncryptBlock encrypt_block;
    AES_BoxDecryptBlock decrypt_block;
    AES_BoxXorBlock xor_block;
    AES_BoxIncBlock inc_block;
    AES_BoxGetBlockSize get_block_size;
    AES_BoxStoreBlock store_block;
    AES_BoxLoadBlock load_block;
}
AES_BoxAlgorithmInterface;

typedef struct
{
    const AES_BoxAlgorithmInterface* algorithm;
    AES_BoxEncryptionRoundKeys encryption_keys;
    AES_BoxDecryptionRoundKeys decryption_keys;
    AES_Mode mode;
    AES_BoxBlock iv;
}
AES_Box;

#ifdef __cplusplus
}
#endif

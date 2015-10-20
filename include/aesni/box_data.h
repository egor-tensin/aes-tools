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
    AesNI_AES128_Key aes128_key;
    AesNI_AES192_Key aes192_key;
    AesNI_AES256_Key aes256_key;
}
AesNI_BoxKey;

typedef union
{
    AesNI_AES128_RoundKeys aes128_encryption_keys;
    AesNI_AES192_RoundKeys aes192_encryption_keys;
    AesNI_AES256_RoundKeys aes256_encryption_keys;
}
AesNI_BoxEncryptionRoundKeys;

typedef union
{
    AesNI_AES128_RoundKeys aes128_decryption_keys;
    AesNI_AES192_RoundKeys aes192_decryption_keys;
    AesNI_AES256_RoundKeys aes256_decryption_keys;
}
AesNI_BoxDecryptionRoundKeys;

typedef union
{
    AesNI_AES128_KeyString aes128;
    AesNI_AES192_KeyString aes192;
    AesNI_AES256_KeyString aes256;
}
AesNI_BoxKeyString;

typedef union
{
    AesNI_AES_Block aes_block;
}
AesNI_BoxBlock;

typedef union
{
    AesNI_AES_BlockString aes;
}
AesNI_BoxBlockString;

typedef AesNI_StatusCode (*AesNI_BoxCalculateRoundKeys)(
    const AesNI_BoxKey* params,
    AesNI_BoxEncryptionRoundKeys*,
    AesNI_BoxDecryptionRoundKeys*,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxParseBlock)(
    AesNI_BoxBlock* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxParseKey)(
    AesNI_BoxKey* dest,
    const char* src,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxFormatBlock)(
    AesNI_BoxBlockString* dest,
    const AesNI_BoxBlock* src,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxFormatKey)(
    AesNI_BoxKeyString* dest,
    const AesNI_BoxKey* src,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxEncryptBlock)(
    const AesNI_BoxBlock* plaintext,
    const AesNI_BoxEncryptionRoundKeys* params,
    AesNI_BoxBlock* ciphertext,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxDecryptBlock)(
    const AesNI_BoxBlock* ciphertext,
    const AesNI_BoxDecryptionRoundKeys* params,
    AesNI_BoxBlock* plaintext,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxXorBlock)(
    AesNI_BoxBlock*,
    const AesNI_BoxBlock*,
    AesNI_ErrorDetails*);

typedef AesNI_StatusCode (*AesNI_BoxIncBlock)(
    AesNI_BoxBlock*,
    AesNI_ErrorDetails*);

typedef AesNI_StatusCode (*AesNI_BoxGetBlockSize)(
    size_t*,
    AesNI_ErrorDetails*);

typedef AesNI_StatusCode (*AesNI_BoxStoreBlock)(
    void*,
    const AesNI_BoxBlock*,
    AesNI_ErrorDetails*);

typedef AesNI_StatusCode (*AesNI_BoxLoadBlock)(
    AesNI_BoxBlock*,
    const void*,
    AesNI_ErrorDetails*);

typedef struct
{
    AesNI_BoxCalculateRoundKeys calc_round_keys;
    AesNI_BoxParseBlock parse_block;
    AesNI_BoxParseKey parse_key;
    AesNI_BoxFormatBlock format_block;
    AesNI_BoxFormatKey format_key;
    AesNI_BoxEncryptBlock encrypt_block;
    AesNI_BoxDecryptBlock decrypt_block;
    AesNI_BoxXorBlock xor_block;
    AesNI_BoxIncBlock inc_block;
    AesNI_BoxGetBlockSize get_block_size;
    AesNI_BoxStoreBlock store_block;
    AesNI_BoxLoadBlock load_block;
}
AesNI_BoxAlgorithmInterface;

typedef struct
{
    const AesNI_BoxAlgorithmInterface* algorithm;
    AesNI_BoxEncryptionRoundKeys encryption_keys;
    AesNI_BoxDecryptionRoundKeys decryption_keys;
    AesNI_Mode mode;
    AesNI_BoxBlock iv;
}
AesNI_Box;

#ifdef __cplusplus
}
#endif

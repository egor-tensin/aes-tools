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

#ifdef __cplusplus
extern "C"
{
#endif

typedef union
{
    AesNI_Aes128_Key aes128_key;
    AesNI_Aes192_Key aes192_key;
    AesNI_Aes256_Key aes256_key;
}
AesNI_BoxAlgorithmParams;

typedef enum
{
    AESNI_AES128,
    AESNI_AES192,
    AESNI_AES256,
}
AesNI_BoxAlgorithm;

typedef enum
{
    AESNI_ECB,
    AESNI_CBC,
    AESNI_CFB,
    AESNI_OFB,
    AESNI_CTR,
}
AesNI_BoxMode;

typedef union
{
    AesNI_Aes128_RoundKeys aes128_encryption_keys;
    AesNI_Aes192_RoundKeys aes192_encryption_keys;
    AesNI_Aes256_RoundKeys aes256_encryption_keys;
}
AesNI_BoxEncryptionParams;

typedef union
{
    AesNI_Aes128_RoundKeys aes128_decryption_keys;
    AesNI_Aes192_RoundKeys aes192_decryption_keys;
    AesNI_Aes256_RoundKeys aes256_decryption_keys;
}
AesNI_BoxDecryptionParams;

typedef union
{
    AesNI_Aes_Block aes_block;
}
AesNI_BoxBlock;

typedef AesNI_StatusCode (*AesNI_BoxDeriveParams)(
    const AesNI_BoxAlgorithmParams* params,
    AesNI_BoxEncryptionParams*,
    AesNI_BoxDecryptionParams*,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxEncrypt)(
    const AesNI_BoxBlock* plaintext,
    const AesNI_BoxEncryptionParams* params,
    AesNI_BoxBlock* ciphertext,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxDecrypt)(
    const AesNI_BoxBlock* ciphertext,
    const AesNI_BoxDecryptionParams* params,
    AesNI_BoxBlock* plaintext,
    AesNI_ErrorDetails* err_details);

typedef AesNI_StatusCode (*AesNI_BoxXorBlock)(
    AesNI_BoxBlock*,
    const AesNI_BoxBlock*,
    AesNI_ErrorDetails*);

typedef AesNI_StatusCode (*AesNI_BoxIncCounter)(
    AesNI_BoxBlock*,
    AesNI_ErrorDetails*);

typedef struct
{
    AesNI_BoxDeriveParams derive_params;
    AesNI_BoxEncrypt encrypt;
    AesNI_BoxDecrypt decrypt;
    AesNI_BoxXorBlock xor_block;
    AesNI_BoxIncCounter inc_counter;
}
AesNI_BoxAlgorithmInterface;

typedef struct
{
    const AesNI_BoxAlgorithmInterface* algorithm_iface;
    AesNI_BoxEncryptionParams encrypt_params;
    AesNI_BoxDecryptionParams decrypt_params;
    AesNI_BoxMode mode;
    AesNI_BoxBlock iv;
}
AesNI_Box;

#ifdef __cplusplus
}
#endif

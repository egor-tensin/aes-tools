/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

AesNI_BoxAlgorithmInterface aesni_box_aes128_iface =
{
    &aesni_box_derive_params_aes128,
    &aesni_box_encrypt_aes128,
    &aesni_box_decrypt_aes128,
    &aesni_box_xor_block_aes,
};

AesNI_BoxAlgorithmInterface aesni_box_aes192_iface =
{
    &aesni_box_derive_params_aes192,
    &aesni_box_encrypt_aes192,
    &aesni_box_decrypt_aes192,
    &aesni_box_xor_block_aes,
};

AesNI_BoxAlgorithmInterface aesni_box_aes256_iface =
{
    &aesni_box_derive_params_aes256,
    &aesni_box_encrypt_aes256,
    &aesni_box_decrypt_aes256,
    &aesni_box_xor_block_aes,
};

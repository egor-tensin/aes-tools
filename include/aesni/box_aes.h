/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "box_data.h"

#ifdef __cplusplus
extern "C"
{
#endif

extern AesNI_BoxAlgorithmInterface aesni_box_aes128_iface;
extern AesNI_BoxAlgorithmInterface aesni_box_aes192_iface;
extern AesNI_BoxAlgorithmInterface aesni_box_aes256_iface;

#ifdef __cplusplus
}
#endif

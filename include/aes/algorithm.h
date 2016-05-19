/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    AESNI_AES128,
    AESNI_AES192,
    AESNI_AES256,
}
AesNI_Algorithm;

#ifdef __cplusplus
}
#endif

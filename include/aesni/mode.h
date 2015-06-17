/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

typedef enum
{
    AESNI_ECB,
    AESNI_CBC,
    AESNI_CFB,
    AESNI_OFB,
    AESNI_CTR,
}
AesNI_Mode;

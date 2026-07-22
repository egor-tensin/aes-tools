// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AES_ECB,
    AES_CBC,
    AES_CFB,
    AES_OFB,
    AES_CTR,
} AES_Mode;

static inline int aes_mode_requires_init_vector(AES_Mode mode) {
    return mode != AES_ECB;
}

#ifdef __cplusplus
}
#endif

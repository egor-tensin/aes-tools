// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    AES_AES128,
    AES_AES192,
    AES_AES256,
}
AES_Algorithm;

#ifdef __cplusplus
}
#endif

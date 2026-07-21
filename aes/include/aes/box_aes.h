// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "box_data.h"

#ifdef __cplusplus
extern "C" {
#endif

extern AES_BoxOps aes128_box_ops;
extern AES_BoxOps aes192_box_ops;
extern AES_BoxOps aes256_box_ops;

#ifdef __cplusplus
}
#endif

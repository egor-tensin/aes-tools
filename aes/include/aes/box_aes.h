// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "box_data.h"

#ifdef __cplusplus
extern "C" {
#endif

extern AES_BoxInterface aes128_box_interface;
extern AES_BoxInterface aes192_box_interface;
extern AES_BoxInterface aes256_box_interface;

#ifdef __cplusplus
}
#endif

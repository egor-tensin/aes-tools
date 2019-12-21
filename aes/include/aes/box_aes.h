// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "box_data.h"

#ifdef __cplusplus
extern "C"
{
#endif

extern AES_BoxAlgorithmInterface aes_box_algorithm_aes128;
extern AES_BoxAlgorithmInterface aes_box_algorithm_aes192;
extern AES_BoxAlgorithmInterface aes_box_algorithm_aes256;

#ifdef __cplusplus
}
#endif

// Copyright (c) 2026 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "error.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

AES_StatusCode aes_parse_hex_string(
    unsigned char* dest,
    const char* src,
    size_t numof_bytes,
    AES_ErrorDetails* err_details
);

#ifdef __cplusplus
}
#endif

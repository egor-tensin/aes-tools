/*
 * Copyright (c) 2026 Egor Tensin <Egor.Tensin@gmail.com>
 * This file is part of the "AES tools" project.
 * For details, see https://github.com/egor-tensin/aes-tools.
 * Distributed under the MIT License.
 */

#include <aes/all.h>

#include <stdio.h>
#include <stdlib.h>

AES_StatusCode aes_parse_hex_string(
    unsigned char* dest,
    const char* src,
    size_t numof_bytes,
    AES_ErrorDetails* err_details
) {
    if (dest == NULL)
        return aes_error_null_argument(err_details, "dest");
    if (src == NULL)
        return aes_error_null_argument(err_details, "src");

    char what[30];
    snprintf(what, sizeof(what), "a %zu-byte hex string", numof_bytes);

    const char* cursor = src;

    for (size_t i = 0; i < numof_bytes; ++i) {
        int n;
        unsigned int byte;
        if (sscanf(cursor, "%2x%n", &byte, &n) != 1 || n != 2)
            return aes_error_parse(err_details, src, what);
        dest[i] = (unsigned char)byte;
        cursor += n;
    }

    if (*cursor != '\0')
        return aes_error_parse(err_details, src, what);

    return AES_SUCCESS;
}

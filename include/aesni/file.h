/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <stdio.h>

size_t aes128ecb_encrypt_file(const unsigned char* src,
                              size_t src_size,
                              unsigned char* dest,
                              Aes128KeySchedule* key_schedule);
size_t aes128ecb_decrypt_file(const unsigned char* src,
                              size_t src_size,
                              unsigned char* dest,
                              Aes128KeySchedule* inverted_schedule);

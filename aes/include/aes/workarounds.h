// Copyright (c) 2016 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#if defined(_MSC_VER)
#define AES_ALIGN(t, x) __declspec(align(x)) t
#elif defined(__GNUC__) || defined(__MINGW32__)
#define AES_ALIGN(t, x) t __attribute__((aligned(x)))
#else
#warning "couldn't determine alignment attribute"
#endif

#define AES_UNUSED_PARAMETER(...) (void) (__VA_ARGS__)

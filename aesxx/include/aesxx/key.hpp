// Copyright (c) 2015 Egor Tensin <egor@tensin.name>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "algorithm.hpp"
#include "error.hpp"

#include <aes/all.h>

#include <string>
#include <string_view>

namespace aes {

class Key {
public:
    using Impl = AES_Key;

    static Key parse(std::string_view src, Algorithm algorithm) {
        Impl dest;
        aes_parse_key(algorithm, &dest, src.data(), ErrorDetailsThrowsInDestructor{});
        return Key{dest, algorithm};
    }

    explicit Key(const Impl& impl, Algorithm algorithm) : impl{impl}, algorithm{algorithm} {}

    Impl* ptr() {
        return &impl;
    }

    const Impl* ptr() const {
        return &impl;
    }

    std::string to_string() const {
        AES_KeyString str;
        aes_format_key(algorithm, &str, &impl, ErrorDetailsThrowsInDestructor{});
        return reinterpret_cast<const char*>(&str);
    }

private:
    Impl impl;
    Algorithm algorithm;
};

} // namespace aes

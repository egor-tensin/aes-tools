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

class Block {
public:
    using Impl = AES_Block;

    static Block parse(std::string_view src) {
        Impl dest;
        aes_parse_block(&dest, src.data(), ErrorDetailsThrowsInDestructor{});
        return Block{dest};
    }

    explicit Block(Impl impl) : impl{impl} {}

    Block(int hi3, int hi2, int lo1, int lo0) : impl{aes_make_block(hi3, hi2, lo1, lo0)} {}

    Block() : Block{0, 0, 0, 0} {}

    Impl* ptr() {
        return &impl;
    }

    const Impl* ptr() const {
        return &impl;
    }

    std::string to_string() const {
        AES_BlockString str;
        aes_format_block(&str, &impl, ErrorDetailsThrowsInDestructor{});
        return str.str;
    }

    std::string to_matrix_string() const {
        AES_BlockMatrixString str;
        aes_format_block_as_matrix(&str, &impl, ErrorDetailsThrowsInDestructor{});
        return str.str;
    }

private:
    Impl impl;
};

} // namespace aes

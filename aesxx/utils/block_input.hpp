// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

class Input {
public:
    Input(std::string_view key, std::string_view iv, std::vector<std::string>&& blocks)
        : key{key}, iv{iv}, blocks{std::move(blocks)} {}

    Input(std::string key, std::vector<std::string>&& blocks)
        : key{key}, blocks{std::move(blocks)} {}

    const std::string key;
    const std::string iv;
    const std::vector<std::string> blocks;
};

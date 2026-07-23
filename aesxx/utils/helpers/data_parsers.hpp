// Copyright (c) 2015 Egor Tensin <egor@tensin.name>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <aesxx/all.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/any.hpp>
#include <boost/program_options.hpp>

#include <string>
#include <unordered_map>
#include <vector>

namespace boost {

inline void validate(any& dest, const std::vector<std::string>& values, aes::Mode*, int) {
    using namespace program_options;

    validators::check_first_occurrence(dest);
    const auto& src = validators::get_single_string(values);

    static const std::unordered_map<std::string, aes::Mode> lookup_table = {
        {"ecb", AES_ECB},
        {"cbc", AES_CBC},
        {"cfb", AES_CFB},
        {"ofb", AES_OFB},
        {"ctr", AES_CTR},
    };

    const auto it = lookup_table.find(algorithm::to_lower_copy(src));
    if (it == lookup_table.cend())
        throw invalid_option_value(src);
    dest = it->second;
}

inline void validate(any& dest, const std::vector<std::string>& values, aes::Algorithm*, int) {
    using namespace program_options;

    validators::check_first_occurrence(dest);
    const auto& src = validators::get_single_string(values);

    static const std::unordered_map<std::string, aes::Algorithm> lookup_table = {
        {"aes128", AES_AES128},
        {"aes192", AES_AES192},
        {"aes256", AES_AES256},
    };

    const auto it = lookup_table.find(algorithm::to_lower_copy(src));
    if (it == lookup_table.cend())
        throw invalid_option_value(src);
    dest = it->second;
}

inline void validate(any& dest, const std::vector<std::string>& values, aes::Block*, int) {
    const std::string& src = program_options::validators::get_single_string(values);
    dest = aes::Block{src};
}

} // namespace boost

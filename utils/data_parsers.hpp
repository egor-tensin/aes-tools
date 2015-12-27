/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <aesnixx/all.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

#include <istream>
#include <map>
#include <string>

static std::istream& operator>>(std::istream& is, aesni::Mode& dest)
{
    static const char* const argument_name = "mode";

    std::string src;
    is >> src;

    static std::map<std::string, aesni::Mode> lookup_table =
    {
        { "ecb", AESNI_ECB },
        { "cbc", AESNI_CBC },
        { "cfb", AESNI_CFB },
        { "ofb", AESNI_OFB },
        { "ctr", AESNI_CTR },
    };

    const auto it = lookup_table.find(boost::algorithm::to_lower_copy(src));

    if (it == lookup_table.cend())
        throw boost::program_options::invalid_option_value(src);

    dest = it->second;
    return is;
}

static std::istream& operator>>(std::istream& is, aesni::Algorithm& dest)
{
    static const char* const argument_name = "algorithm";

    std::string src;
    is >> src;

    static std::map<std::string, aesni::Algorithm> lookup_table =
    {
        { "aes128", AESNI_AES128 },
        { "aes192", AESNI_AES192 },
        { "aes256", AESNI_AES256 },
    };

    const auto it = lookup_table.find(boost::algorithm::to_lower_copy(src));

    if (it == lookup_table.cend())
        throw boost::program_options::invalid_option_value(src);

    dest = it->second;
    return is;
}

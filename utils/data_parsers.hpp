/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <aesxx/all.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

#include <istream>
#include <map>
#include <string>

static std::istream& operator>>(std::istream& is, aes::Mode& dest)
{
    static const char* const argument_name = "mode";

    std::string src;
    is >> src;

    static std::map<std::string, aes::Mode> lookup_table =
    {
        { "ecb", AES_ECB },
        { "cbc", AES_CBC },
        { "cfb", AES_CFB },
        { "ofb", AES_OFB },
        { "ctr", AES_CTR },
    };

    const auto it = lookup_table.find(boost::algorithm::to_lower_copy(src));

    if (it == lookup_table.cend())
        throw boost::program_options::invalid_option_value(src);

    dest = it->second;
    return is;
}

static std::istream& operator>>(std::istream& is, aes::Algorithm& dest)
{
    static const char* const argument_name = "algorithm";

    std::string src;
    is >> src;

    static std::map<std::string, aes::Algorithm> lookup_table =
    {
        { "aes128", AES_AES128 },
        { "aes192", AES_AES192 },
        { "aes256", AES_AES256 },
    };

    const auto it = lookup_table.find(boost::algorithm::to_lower_copy(src));

    if (it == lookup_table.cend())
        throw boost::program_options::invalid_option_value(src);

    dest = it->second;
    return is;
}

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <string>
#include <vector>

namespace
{
    class Input
    {
    public:
        Input(const std::string& key_string,
                   const std::string& iv_string,
                   const std::vector<std::string>& input_block_strings)
            : key_string(key_string)
            , iv_string(iv_string)
            , input_block_strings(input_block_strings)
        { }

        Input(const std::string& key_string,
                   const std::vector<std::string>& input_block_strings)
            : key_string(key_string)
            , input_block_strings(input_block_strings)
        { }

        const std::string& get_key_string() const { return key_string; }

        const std::string& get_iv_string() const { return iv_string; }

        const std::vector<std::string>& get_input_block_strings() const
        {
            return input_block_strings;
        }

    private:
        const std::string key_string;
        const std::string iv_string;
        const std::vector<std::string> input_block_strings;
    };
}

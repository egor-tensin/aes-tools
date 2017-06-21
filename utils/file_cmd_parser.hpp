// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "data_parsers.hpp"
#include "helpers/command_line.hpp"

#include <aesxx/all.hpp>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <ostream>
#include <string>
#include <utility>

namespace
{
    class FileSettings : public command_line::SettingsParser
    {
    public:
        aes::Algorithm algorithm = AES_AES128;
        aes::Mode mode = AES_ECB;

        std::string input_path;
        std::string output_path;
        std::string key;
        std::string iv;

        explicit FileSettings(const std::string& argv0)
            : SettingsParser{argv0}
        {
            visible.add_options()
                ("algorithm,a",
                    boost::program_options::value<aes::Algorithm>(&algorithm)
                        ->required()
                        ->value_name("NAME"),
                    "set algorithm")
                ("mode,m",
                    boost::program_options::value<aes::Mode>(&mode)
                        ->required()
                        ->value_name("MODE"),
                    "set mode of operation")
                ("key,k",
                    boost::program_options::value<std::string>(&key)
                        ->required()
                        ->value_name("KEY"),
                    "set encryption key")
                ("iv,v",
                    boost::program_options::value<std::string>(&iv)
                        ->value_name("BLOCK"),
                    "set initialization vector")
                ("input,i",
                    boost::program_options::value<std::string>(&input_path)
                        ->required()
                        ->value_name("PATH"),
                    "set input file path")
                ("output,o",
                    boost::program_options::value<std::string>(&output_path)
                        ->required()
                        ->value_name("PATH"),
                    "set output file path");
        }

        const char* get_short_description() const override
        {
            return "[-h|--help] [-a|--algorithm NAME] [-m|--mode MODE]"
                   " [-k|--key KEY] [-v|--iv BLOCK]"
                   " [-i|--input PATH] [-o|--output PATH]";
        }

        void parse(int argc, char** argv) override
        {
            SettingsParser::parse(argc, argv);

            if (aes::mode_requires_init_vector(mode) && iv.empty())
            {
                throw boost::program_options::error{
                    "an initialization vector is required for the selected mode of operation"};
            }
        }
    };
}

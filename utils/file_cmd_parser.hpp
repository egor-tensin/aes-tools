// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "data_parsers.hpp"

#include <aesxx/all.hpp>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <ostream>
#include <string>
#include <utility>

namespace
{
    class CommandLineParser;

    class Settings
    {
    public:
        aes::Algorithm algorithm = AES_AES128;
        aes::Mode mode = AES_ECB;

        std::string input_path;
        std::string output_path;
        std::string key;
        std::string iv;

    private:
        Settings() = default;

        friend class CommandLineParser;
    };

    class CommandLineParser
    {
    public:
        explicit CommandLineParser(const std::string& argv0)
            : prog_name{boost::filesystem::path{argv0}.filename().string()}
            , options{"Options"}
        { }

        Settings parse(int argc, char** argv)
        {
            Settings settings;

            namespace po = boost::program_options;

            options.add_options()
                ("help,h",     "show this message and exit")
                ("mode,m",      po::value<aes::Mode>(&settings.mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aes::Algorithm>(&settings.algorithm)->required(), "set algorithm")
                ("input,i",     po::value<std::string>(&settings.input_path)->required(), "set input file path")
                ("output,o",    po::value<std::string>(&settings.output_path)->required(), "set output file path")
                ("key,k",       po::value<std::string>(&settings.key)->required(), "set encryption key")
                ("iv,v",        po::value<std::string>(&settings.iv), "set initialization vector");

            po::variables_map vm;
            po::store(po::parse_command_line(argc, argv, options), vm);

            if (vm.count("help"))
            {
                help_flag = true;
                return settings;
            }

            po::notify(vm);

            if (aes::mode_requires_init_vector(settings.mode))
            {
                if (!vm.count("iv"))
                {
                    throw boost::program_options::error(
                        "an initialization vector is required for the selected mode of operation");
                }
            }

            return settings;
        }

        bool exit_with_usage() const { return help_flag; }

    private:
        const std::string prog_name;
        boost::program_options::options_description options;

        bool help_flag = false;

        friend std::ostream& operator<<(std::ostream&, const CommandLineParser&);
    };

    std::ostream& operator<<(std::ostream& os, const CommandLineParser& cmd_parser)
    {
        return os << "Usage: " << cmd_parser.prog_name << " [OPTION...]\n"
                  << cmd_parser.options << "\n";
    }
}

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

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
        Settings() = default;

        aesni::Mode get_mode() const { return mode; }
        aesni::Algorithm get_algorithm() const { return algorithm; }

        const std::string& get_input_path() const { return input_path; }
        const std::string& get_output_path() const { return output_path; }

        const std::string& get_key_string() const { return key; }
        const std::string& get_iv_string() const { return iv; }

    private:
        aesni::Mode mode;
        aesni::Algorithm algorithm;

        std::string input_path;
        std::string output_path;
        std::string key;
        std::string iv;

        friend class CommandLineParser;
    };

    class CommandLineParser
    {
    public:
        CommandLineParser(const std::string& argv0)
            : prog_name(boost::filesystem::path(argv0).filename().string())
            , options("Options")
        { }

        void parse(Settings& settings, int argc, char** argv)
        {
            namespace po = boost::program_options;

            options.add_options()
                ("help,h", "show this message and exit")
                ("mode,m", po::value<aesni::Mode>(&settings.mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aesni::Algorithm>(&settings.algorithm)->required(), "set algorithm")
                ("input-path,i", po::value<std::string>(&settings.input_path)->required(), "set input file path")
                ("output-path,o", po::value<std::string>(&settings.output_path)->required(), "set output file path")
                ("key,k", po::value<std::string>(&settings.key)->required(), "set encryption key")
                ("iv,v", po::value<std::string>(&settings.iv), "set initialization vector");

            po::variables_map vm;
            po::store(po::parse_command_line(argc, argv, options), vm);

            if (vm.count("help"))
            {
                help_flag = true;
                return;
            }

            po::notify(vm);

            if (aesni::mode_requires_initialization_vector(settings.get_mode()))
            {
                if (!vm.count("iv"))
                {
                    throw boost::program_options::error(
                        "an initialization vector is required for the selected mode of operation");
                }
            }
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

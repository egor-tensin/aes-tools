/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "data_parsers.hpp"

#include <aesnixx/all.hpp>

#include <boost/program_options.hpp>

#include <ostream>
#include <string>
#include <vector>

namespace
{
    class CommandLineParser
    {
    public:
        CommandLineParser(const char* prog_name)
            : prog_name(prog_name)
            , options("Options")
        {
            namespace po = boost::program_options;

            options.add_options()
                ("help,h", "show this message and exit")
                ("mode,m", po::value<aesni::Mode>(&mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aesni::Algorithm>(&algorithm)->required(), "set algorithm");
        }

        void parse(int argc, char** argv)
        {
            namespace po = boost::program_options;

            po::options_description hidden_options;
            hidden_options.add_options()
                ("positional", po::value<std::vector<std::string>>(&args));

            po::options_description all_options;
            all_options.add(options).add(hidden_options);

            po::positional_options_description positional_options;
            positional_options.add("positional", -1);

            po::variables_map vm;
            po::store(po::command_line_parser(argc, argv).options(all_options).positional(positional_options).run(), vm);

            if (vm.count("help"))
            {
                help_flag = true;
                return;
            }

            po::notify(vm);
        }

        bool requested_help() const { return help_flag; }

        aesni::Mode mode;
        aesni::Algorithm algorithm;
        std::vector<std::string> args;

    private:
        const std::string prog_name;
        boost::program_options::options_description options;

        bool help_flag = false;

        friend std::ostream& operator<<(std::ostream&, const CommandLineParser&);
    };

    std::ostream& operator<<(std::ostream& os, const CommandLineParser& cmd_parser)
    {
        return os << "Usage: " << cmd_parser.prog_name << " [OPTIONS...] KEY [IV] SRC_PATH DEST_PATH\n"
                  << cmd_parser.options << "\n";
    }
}

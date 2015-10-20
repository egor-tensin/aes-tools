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

#include <boost/config.hpp>
#include <boost/program_options.hpp>

#include <ostream>
#include <string>
#include <vector>

namespace
{
    BOOST_NORETURN inline void throw_iv_required()
    {
        throw boost::program_options::error(
            "initialization vector is required for the selected mode of operation");
    }

    BOOST_NORETURN inline void throw_not_implemented(aesni::Algorithm algorithm)
    {
        throw boost::program_options::error(
            "the selected algorithm is not implemented");
    }

    BOOST_NORETURN inline void throw_not_implemented(aesni::Mode mode)
    {
        throw boost::program_options::error(
            "the selected mode of operation is not implemented");
    }

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
                ("box,b", po::bool_switch(&use_boxes)->default_value(false), "use the \"boxes\" interface")
                ("mode,m", po::value<aesni::Mode>(&mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aesni::Algorithm>(&algorithm)->required(), "set algorithm")
                ("verbose,v", po::bool_switch(&verbose)->default_value(false), "enable verbose output");
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
        bool use_boxes;
        std::vector<std::string> args;
        bool verbose;

    private:
        const std::string prog_name;
        boost::program_options::options_description options;

        bool help_flag = false;

        friend std::ostream& operator<<(std::ostream&, const CommandLineParser&);
    };

    std::ostream& operator<<(std::ostream& os, const CommandLineParser& cmd_parser)
    {
        return os << "Usage: " << cmd_parser.prog_name << " [OPTIONS...] [-- KEY [IV] [BLOCK...]...]\n"
                  << cmd_parser.options << "\n";
    }
}

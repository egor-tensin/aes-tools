/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "block_input.hpp"
#include "data_parsers.hpp"

#include <aesnixx/all.hpp>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <iterator>
#include <deque>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

namespace
{
    class CommandLineParser;

    class Settings
    {
    public:
        aesni::Algorithm get_algorithm() const { return algorithm; }
        aesni::Mode get_mode() const { return mode; }

        bool use_boxes() const { return use_boxes_flag; }
        bool verbose() const { return verbose_flag; }

    private:
        aesni::Algorithm algorithm;
        aesni::Mode mode;

        bool use_boxes_flag = false;
        bool verbose_flag = false;

        friend class CommandLineParser;
    };

    class CommandLineParser
    {
    public:
        CommandLineParser(const std::string& argv0)
            : prog_name(boost::filesystem::path(argv0).filename().string())
            , options("Options")
        { }

        void parse(Settings& settings, int argc, char** argv, std::vector<Input>& inputs)
        {
            namespace po = boost::program_options;

            options.add_options()
                ("help,h", "show this message and exit")
                ("use-boxes,b", po::bool_switch(&settings.use_boxes_flag)->default_value(false), "use the \"boxes\" interface")
                ("mode,m", po::value<aesni::Mode>(&settings.mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aesni::Algorithm>(&settings.algorithm)->required(), "set algorithm")
                ("verbose,v", po::bool_switch(&settings.verbose_flag)->default_value(false), "enable verbose output");

            std::vector<std::string> args;

            po::options_description hidden_options;
            hidden_options.add_options()
                ("positional", po::value<std::vector<std::string>>(&args));

            po::options_description all_options;
            all_options.add(options).add(hidden_options);

            po::positional_options_description positional_options;
            positional_options.add("positional", -1);

            po::variables_map vm;
            po::store(po::command_line_parser(argc, argv)
                .options(all_options)
                .positional(positional_options)
                .run(), vm);

            if (vm.count("help"))
            {
                help_flag = true;
                return;
            }

            po::notify(vm);

            parse_inputs(settings, inputs, std::deque<std::string>(
                std::make_move_iterator(args.begin()),
                std::make_move_iterator(args.end())
            ));
        }

        bool exit_with_usage() const { return help_flag; }

    private:
        static void parse_inputs(
            const Settings& settings,
            std::vector<Input>& inputs,
            std::deque<std::string>&& args)
        {
            while (!args.empty())
            {
                auto key_string = std::move(args.front());
                args.pop_front();

                std::string iv_string;

                if (aesni::mode_requires_initialization_vector(settings.get_mode()))
                {
                    if (args.empty())
                    {
                        throw boost::program_options::error(
                            "an initialization vector is required for the selected mode of operation");
                    }
                    iv_string = std::move(args.front());
                    args.pop_front();
                }

                std::vector<std::string> input_block_strings;

                while (!args.empty())
                {
                    if (args.front() == "--")
                    {
                        args.pop_front();
                        break;
                    }

                    input_block_strings.emplace_back(std::move(args.front()));
                    args.pop_front();
                }

                if (aesni::mode_requires_initialization_vector(settings.get_mode()))
                {
                    inputs.emplace_back(
                        std::move(key_string),
                        std::move(iv_string),
                        std::move(input_block_strings));
                }
                else
                {
                    inputs.emplace_back(
                        std::move(key_string),
                        std::move(input_block_strings));
                }
            }
        }

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

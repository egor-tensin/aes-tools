// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "block_input.hpp"
#include "data_parsers.hpp"

#include <aesxx/all.hpp>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <deque>
#include <iterator>
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
        aes::Algorithm algorithm = AES_AES128;
        aes::Mode mode = AES_ECB;

        bool use_boxes = false;
        bool verbose = false;

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

        Settings parse(int argc, char** argv, std::vector<Input>& inputs)
        {
            Settings settings;

            namespace po = boost::program_options;

            options.add_options()
                ("help,h",      "show this message and exit")
                ("use-boxes,b", po::bool_switch(&settings.use_boxes)->default_value(false), "use the \"boxes\" interface")
                ("mode,m",      po::value<aes::Mode>(&settings.mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aes::Algorithm>(&settings.algorithm)->required(), "set algorithm")
                ("verbose,v",   po::bool_switch(&settings.verbose)->default_value(false), "enable verbose output");

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
                return settings;
            }

            po::notify(vm);

            inputs = parse_inputs(settings, std::deque<std::string>{
                std::make_move_iterator(args.begin()),
                std::make_move_iterator(args.end())});

            return settings;
        }

        bool exit_with_usage() const { return help_flag; }

    private:
        static std::vector<Input> parse_inputs(
            const Settings& settings,
            std::deque<std::string>&& args)
        {
            std::vector<Input> inputs;
            while (!args.empty())
                inputs.emplace_back(parse_input(settings, args));
            return inputs;
        }

        static Input parse_input(
            const Settings& settings,
            std::deque<std::string>& args)
        {
            std::string key{std::move(args.front())};
            args.pop_front();

            std::string iv;

            if (aes::mode_requires_init_vector(settings.mode))
            {
                if (args.empty())
                    throw boost::program_options::error{"an initialization vector is required for the selected mode of operation"};
                iv = std::move(args.front());
                args.pop_front();
            }

            auto blocks = parse_blocks(args);

            if (aes::mode_requires_init_vector(settings.mode))
                return {key, iv, std::move(blocks)};
            else
                return {key, std::move(blocks)};
        }

        static std::vector<std::string> parse_blocks(std::deque<std::string>& args)
        {
            std::vector<std::string> blocks;

            while (!args.empty())
            {
                std::string block{std::move(args.front())};
                args.pop_front();
                if (block == "--")
                    break;
                blocks.emplace_back(std::move(block));
            }

            return blocks;
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

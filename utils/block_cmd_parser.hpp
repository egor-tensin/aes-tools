// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "block_input.hpp"
#include "data_parsers.hpp"
#include "helpers/command_line.hpp"

#include <aesxx/all.hpp>

#include <boost/program_options.hpp>

#include <deque>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace
{
    class BlockSettings : public command_line::SettingsParser
    {
    public:
        aes::Algorithm algorithm = AES_AES128;
        aes::Mode mode = AES_ECB;

        bool use_boxes = false;
        bool verbose = false;

        std::vector<Input> inputs;

        explicit BlockSettings(const std::string& argv0)
            : SettingsParser{argv0}
        {
            visible.add_options()
                ("verbose,v",
                    boost::program_options::bool_switch(&verbose),
                    "enable verbose output")
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
                ("use-boxes,b",
                    boost::program_options::bool_switch(&use_boxes),
                    "use the \"boxes\" interface");
            hidden.add_options()
                ("args",
                    boost::program_options::value<std::vector<std::string>>(&args),
                    "shouldn't be visible");
            positional.add("args", -1);
        }

        const char* get_short_description() const override
        {
            return "[-h|--help] [-v|--verbose] [-a|--algorithm NAME] [-m|--mode MODE]"
                   " [-- KEY [IV] [BLOCK]...]...";
        }

        void parse(int argc, char* argv[]) override
        {
            SettingsParser::parse(argc, argv);
            parse_inputs(std::deque<std::string>{
                std::make_move_iterator(args.begin()),
                std::make_move_iterator(args.end())});
        }

    private:
        void parse_inputs(std::deque<std::string>&& src)
        {
            while (!src.empty())
                inputs.emplace_back(parse_input(src));
        }

        Input parse_input(std::deque<std::string>& src) const
        {
            std::string key{std::move(src.front())};
            src.pop_front();

            std::string iv;

            if (aes::mode_requires_init_vector(mode))
            {
                if (src.empty())
                {
                    throw boost::program_options::error{
                        "an initialization vector is required for the selected mode of operation"};
                }
                iv = std::move(src.front());
                src.pop_front();
            }

            auto blocks = parse_blocks(src);

            if (aes::mode_requires_init_vector(mode))
                return {key, iv, std::move(blocks)};
            else
                return {key, std::move(blocks)};
        }

        static std::vector<std::string> parse_blocks(std::deque<std::string>& src)
        {
            std::vector<std::string> blocks;

            while (!src.empty())
            {
                std::string block{std::move(src.front())};
                src.pop_front();
                if (block == "--")
                    break;
                blocks.emplace_back(std::move(block));
            }

            return blocks;
        }

        std::vector<std::string> args;
    };
}

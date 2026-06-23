// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "cmd_parser.hpp"
#include "data_parsers.hpp"

#include <aesxx/all.hpp>

#include <boost/program_options.hpp>

#include <deque>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

class BlockSettings : public SettingsParser {
public:
    class Input {
    public:
        Input(std::string_view key, std::string_view iv, std::vector<std::string>&& blocks)
            : key{key}, iv{iv}, blocks{std::move(blocks)} {}

        Input(std::string key, std::vector<std::string>&& blocks)
            : key{key}, blocks{std::move(blocks)} {}

        std::string get_key() const {
            return key;
        }

        bool has_iv() const {
            return !iv.empty();
        }

        std::string get_iv() const {
            return iv;
        }

        std::vector<std::string> get_blocks() const {
            return blocks;
        }

    private:
        std::string key;
        std::string iv;
        std::vector<std::string> blocks;
    };

    explicit BlockSettings(std::string_view argv0) : SettingsParser{argv0} {
        visible.add_options()(
            "verbose,v", boost::program_options::bool_switch(&_verbose), "enable verbose output"
        );
        visible.add_options()(
            "algorithm,a",
            boost::program_options::value<aes::Algorithm>(&algorithm)
                ->required()
                ->value_name("NAME"),
            "set algorithm"
        );
        visible.add_options()(
            "mode,m",
            boost::program_options::value<aes::Mode>(&mode)->required()->value_name("MODE"),
            "set mode of operation"
        );
        visible.add_options()(
            "use-boxes,b",
            boost::program_options::bool_switch(&_use_boxes),
            "use the \"boxes\" interface"
        );
    }

    const char* get_short_description() const override {
        return "[-h|--help] [-v|--verbose] [-a|--algorithm NAME] [-m|--mode MODE]"
               " [-- KEY [IV] [BLOCK]...]...";
    }

    void parse(int argc, char* argv[]) override {
        std::vector<std::string> args;
        hidden.add_options()(
            "args",
            boost::program_options::value<std::vector<std::string>>(&args),
            "shouldn't be visible"
        );
        positional.add("args", -1);

        SettingsParser::parse(argc, argv);
        if (exit_with_usage())
            return;

        parse_inputs(
            std::deque<std::string>{
                std::make_move_iterator(args.begin()), std::make_move_iterator(args.end())
            }
        );
    }

    aes::Algorithm get_algorithm() const {
        return algorithm;
    }

    aes::Mode get_mode() const {
        return mode;
    }

    const std::vector<Input>& get_inputs() const {
        return inputs;
    }

    bool use_boxes() const {
        return _use_boxes;
    }

    bool verbose() const {
        return _verbose;
    }

private:
    void parse_inputs(std::deque<std::string>&& src) {
        while (!src.empty())
            inputs.emplace_back(parse_input(src));
    }

    Input parse_input(std::deque<std::string>& src) const {
        std::string key{std::move(src.front())};
        src.pop_front();

        std::string iv;

        if (aes::mode_requires_init_vector(mode)) {
            if (src.empty()) {
                throw boost::program_options::error{
                    "an initialization vector is required for the selected mode of operation"
                };
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

    static std::vector<std::string> parse_blocks(std::deque<std::string>& src) {
        std::vector<std::string> blocks;

        while (!src.empty()) {
            std::string block{std::move(src.front())};
            src.pop_front();
            if (block == "--")
                break;
            blocks.emplace_back(std::move(block));
        }

        return blocks;
    }

    aes::Algorithm algorithm;
    aes::Mode mode;
    std::vector<Input> inputs;

    bool _use_boxes = false;
    bool _verbose = false;
};

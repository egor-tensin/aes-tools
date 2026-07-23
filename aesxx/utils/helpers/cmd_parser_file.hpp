// Copyright (c) 2015 Egor Tensin <egor@tensin.name>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "cmd_parser.hpp"
#include "data_parsers.hpp"

#include <aesxx/all.hpp>

#include <boost/optional.hpp>
#include <boost/program_options.hpp>

#include <optional>
#include <string>
#include <string_view>

class FileSettings : public SettingsParser {
public:
    explicit FileSettings(std::string_view argv0) : SettingsParser{argv0} {
        namespace po = boost::program_options;

        visible.add_options()(
            "algorithm,a", po::value(&algorithm)->required()->value_name("NAME"), "set algorithm"
        );
        visible.add_options()(
            "mode,m", po::value(&mode)->required()->value_name("MODE"), "set mode of operation"
        );
        visible.add_options()(
            "key,k", po::value(&key)->required()->value_name("KEY"), "set encryption key"
        );
        visible.add_options()(
            "iv,v", po::value(&iv)->value_name("BLOCK"), "set initialization vector"
        );
        visible.add_options()(
            "input,i", po::value(&input_path)->required()->value_name("PATH"), "set input file path"
        );
        visible.add_options()(
            "output,o",
            po::value(&output_path)->required()->value_name("PATH"),
            "set output file path"
        );
    }

    const char* get_short_description() const override {
        return "[-h|--help] [-a|--algorithm NAME] [-m|--mode MODE]"
               " [-k|--key KEY] [-v|--iv BLOCK]"
               " [-i|--input PATH] [-o|--output PATH]";
    }

    void parse(int argc, char** argv) override {
        SettingsParser::parse(argc, argv);
        if (exit_with_usage())
            return;
    }

    aes::Algorithm get_algorithm() const {
        return algorithm;
    }

    aes::Mode get_mode() const {
        return mode;
    }

    std::string get_input_path() const {
        return input_path;
    }

    std::string get_output_path() const {
        return output_path;
    }

    std::string get_key() const {
        return key;
    }

    std::optional<aes::Block> get_iv() const {
        if (iv)
            return {*iv};
        return {};
    }

private:
    aes::Algorithm algorithm;
    aes::Mode mode;

    std::string input_path;
    std::string output_path;

    std::string key;
    boost::optional<aes::Block> iv;
};

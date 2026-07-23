// Copyright (c) 2017 Egor Tensin <egor@tensin.name>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include <boost/program_options.hpp>

#include <exception>
#include <filesystem>
#include <format>
#include <iostream>
#include <ostream>
#include <string>
#include <string_view>

class SettingsParser {
public:
    explicit SettingsParser(std::string_view argv0) : prog_name{extract_filename(argv0)} {
        visible.add_options()("help,h", "show this message and exit");
    }

    virtual ~SettingsParser() = default;

    virtual const char* get_short_description() const {
        return "[--option VALUE]...";
    }

    virtual void parse(int argc, char* argv[]) {
        namespace po = boost::program_options;
        po::options_description all;
        all.add(hidden).add(visible);
        po::variables_map vm;
        po::store(
            po::command_line_parser{argc, argv}.options(all).positional(positional).run(), vm
        );
        if (vm.count("help"))
            _exit_with_usage = true;
        else
            po::notify(vm);
    }

    bool exit_with_usage() const {
        return _exit_with_usage;
    }

    void usage() const {
        std::cout << *this;
    }

    void usage_error(const std::exception& e) const {
        std::cerr << std::format("usage error: {}\n", e.what());
        std::cerr << *this;
    }

protected:
    boost::program_options::options_description hidden;
    boost::program_options::options_description visible;
    boost::program_options::positional_options_description positional;

private:
    static std::string extract_filename(std::string_view path) {
        return std::filesystem::path{path}.filename().string();
    }

    const std::string prog_name;

    friend std::ostream& operator<<(std::ostream& os, const SettingsParser& parser) {
        const auto short_descr = parser.get_short_description();
        os << std::format("usage: {} {}\n", parser.prog_name, short_descr);
        os << parser.visible;
        return os;
    }

    bool _exit_with_usage = false;
};

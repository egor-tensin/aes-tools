// Copyright (c) 2017 Egor Tensin <Egor.Tensin@gmail.com>
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
        boost::program_options::options_description all;
        all.add(hidden).add(visible);
        boost::program_options::variables_map vm;
        boost::program_options::store(
            boost::program_options::command_line_parser{argc, argv}
                .options(all)
                .positional(positional)
                .run(),
            vm
        );
        if (vm.count("help"))
            exit_with_usage = true;
        else
            boost::program_options::notify(vm);
    }

    bool exit_with_usage = false;

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
};

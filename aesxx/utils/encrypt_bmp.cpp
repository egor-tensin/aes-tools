// Copyright (c) 2015 Egor Tensin <egor@tensin.name>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#include "helpers/bmp.hpp"
#include "helpers/cmd_parser_file.hpp"
#include "helpers/file.hpp"

#include <aesxx/all.hpp>

#include <boost/program_options.hpp>

#include <exception>
#include <format>
#include <iostream>
#include <string>

namespace {

void encrypt_bmp(
    aes::Box& box,
    const std::string& plaintext_path,
    const std::string& ciphertext_path
) {
    BmpFile bmp{file::read(plaintext_path)};
    bmp.replace_pixels(box.encrypt_buffer(bmp.get_pixels(), bmp.get_pixels_size()));
    file::write(ciphertext_path, bmp.get_buffer(), bmp.get_size());
}

void encrypt_bmp(const FileSettings& settings) {
    const auto algorithm = settings.get_algorithm();
    const auto mode = settings.get_mode();

    aes::Box::Key key;
    aes::Box::parse_key(key, algorithm, settings.get_key());

    aes::Box box{algorithm, key, mode, settings.get_iv()};
    encrypt_bmp(box, settings.get_input_path(), settings.get_output_path());
}

} // namespace

int main(int argc, char** argv) {
    try {
        FileSettings settings{argv[0]};

        try {
            settings.parse(argc, argv);
        } catch (const boost::program_options::error& e) {
            settings.usage_error(e);
            return 1;
        }

        if (settings.exit_with_usage()) {
            settings.usage();
            return 0;
        }

        encrypt_bmp(settings);
    } catch (const aes::Error& e) {
        std::cerr << e;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << std::format("{}\n", e.what());
        return 1;
    }
    return 0;
}

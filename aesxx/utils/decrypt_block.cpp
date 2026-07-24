// Copyright (c) 2015 Egor Tensin <egor@tensin.name>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#include "helpers/cmd_parser_block.hpp"

#include <aesxx/all.hpp>

#include <boost/program_options.hpp>

#include <exception>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void decrypt_blocks(
    aes::Algorithm algorithm,
    aes::Mode mode,
    const BlockSettings::Input& input,
    bool verbose = false
) {
    const auto key = aes::Key::parse(input.get_key(), algorithm);
    aes::Box box{algorithm, key, mode, input.get_iv(), verbose};

    for (const auto& ciphertext : input.get_blocks()) {
        aes::Block plaintext;
        box.decrypt_block(ciphertext, plaintext);
        std::cout << std::format("{}\n", plaintext.to_string());
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        BlockSettings settings{argv[0]};

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

        for (const auto& input : settings.get_inputs()) {
            decrypt_blocks(
                settings.get_algorithm(), settings.get_mode(), input, settings.get_verbose()
            );
        }
    } catch (const aes::Error& e) {
        std::cerr << e;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << std::format("{}\n", e.what());
        return 1;
    }
    return 0;
}

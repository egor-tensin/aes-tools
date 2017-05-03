// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#include "file_cmd_parser.hpp"
#include "helpers/bmp.hpp"
#include "helpers/file.hpp"

#include <aesxx/all.hpp>

#include <boost/program_options.hpp>

#include <exception>
#include <iostream>
#include <string>

namespace
{
    void encrypt_bmp(
        aes::Box& box,
        const std::string& plaintext_path,
        const std::string& ciphertext_path)
    {
        bmp::BmpFile bmp{file::read_file(plaintext_path)};
        bmp.replace_pixels(box.encrypt_buffer(
            bmp.get_pixels(),
            bmp.get_pixels_size()));
        file::write_file(ciphertext_path, bmp.get_buffer(), bmp.get_size());
    }

    void encrypt_bmp(const Settings& settings)
    {
        const auto algorithm = settings.get_algorithm();
        const auto mode = settings.get_mode();

        const auto& plaintext_path = settings.get_input_path();
        const auto& ciphertext_path = settings.get_output_path();

        aes::Box::Key key;
        aes::Box::parse_key(key, algorithm, settings.get_key_string());

        if (aes::mode_requires_initialization_vector(mode))
        {
            aes::Box::Block iv;
            aes::Box::parse_block(iv, algorithm, settings.get_iv_string());
            aes::Box box{algorithm, key, mode, iv};

            encrypt_bmp(box, plaintext_path, ciphertext_path);
        }
        else
        {
            aes::Box box{algorithm, key};
            encrypt_bmp(box, plaintext_path, ciphertext_path);
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser(argv[0]);
        try
        {
            Settings settings;
            cmd_parser.parse(settings, argc, argv);

            if (cmd_parser.exit_with_usage())
            {
                std::cout << cmd_parser;
                return 0;
            }

            encrypt_bmp(settings);
        }
        catch (const boost::program_options::error& e)
        {
            std::cerr << "Usage error: " << e.what() << "\n";
            std::cerr << cmd_parser;
            return 1;
        }
        catch (const aes::Error& e)
        {
            std::cerr << e;
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }
    return 0;
}

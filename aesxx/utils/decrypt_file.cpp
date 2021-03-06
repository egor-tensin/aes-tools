// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#include "file_cmd_parser.hpp"
#include "helpers/file.hpp"

#include <aesxx/all.hpp>

#include <boost/program_options.hpp>

#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    void decrypt_file(
        aes::Box& box,
        const std::string& ciphertext_path,
        const std::string& plaintext_path)
    {
        const auto ciphertext_buf = file::read_file(ciphertext_path);
        const auto plaintext_buf = box.decrypt_buffer(
            ciphertext_buf.data(),
            ciphertext_buf.size());
        file::write_file(plaintext_path, plaintext_buf);
    }

    void decrypt_file(const FileSettings& settings)
    {
        const auto& algorithm = settings.algorithm;
        const auto& mode = settings.mode;

        aes::Box::Key key;
        aes::Box::parse_key(key, algorithm, settings.key);

        if (aes::mode_requires_init_vector(mode))
        {
            aes::Box::Block iv;
            aes::Box::parse_block(iv, algorithm, settings.iv);

            aes::Box box{algorithm, key, mode, iv};
            decrypt_file(box, settings.input_path, settings.output_path);
        }
        else
        {
            aes::Box box{algorithm, key};
            decrypt_file(box, settings.input_path, settings.output_path);
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        FileSettings settings{argv[0]};

        try
        {
            settings.parse(argc, argv);
        }
        catch (const boost::program_options::error& e)
        {
            settings.usage_error(e);
            return 1;
        }

        if (settings.exit_with_usage)
        {
            settings.usage();
            return 0;
        }

        decrypt_file(settings);
    }
    catch (const aes::Error& e)
    {
        std::cerr << e;
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }
    return 0;
}

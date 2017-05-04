// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#include "block_cmd_parser.hpp"
#include "block_dumper.hpp"
#include "block_input.hpp"

#include <aesxx/all.hpp>

#include <boost/program_options.hpp>

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

namespace
{
    template <aes::Algorithm algorithm, aes::Mode mode>
    void decrypt_with_mode(
        const Input& input,
        bool verbose = false)
    {
        typename aes::Types<algorithm>::Block iv;

        if (aes::ModeRequiresInitVector<mode>())
        {
            aes::from_string<algorithm>(iv, input.get_iv_string());
            if (verbose)
                dump_iv<algorithm>(iv);
        }

        typename aes::Types<algorithm>::Key key;
        aes::from_string<algorithm>(key, input.get_key_string());
        if (verbose)
            dump_key<algorithm>(key);

        aes::DecryptWrapper<algorithm, mode> decrypt(key, iv);
        if (verbose)
            dump_wrapper<algorithm, mode>(decrypt);

        for (const auto& input_block_string : input.get_input_block_strings())
        {
            typename aes::Types<algorithm>::Block ciphertext, plaintext;
            aes::from_string<algorithm>(ciphertext, input_block_string);

            decrypt.decrypt_block(ciphertext, plaintext);

            if (verbose)
            {
                dump_ciphertext<algorithm>(ciphertext);
                dump_plaintext<algorithm>(plaintext);
                dump_next_iv<algorithm, mode>(decrypt);
            }
            else
            {
                std::cout << aes::to_string<algorithm>(plaintext) << '\n';
            }
        }
    }

    template <aes::Algorithm algorithm>
    void decrypt_with_algorithm(
        aes::Mode mode,
        const Input& input,
        bool verbose = false)
    {
        switch (mode)
        {
            case AES_ECB:
                decrypt_with_mode<algorithm, AES_ECB>(input, verbose);
                break;

            case AES_CBC:
                decrypt_with_mode<algorithm, AES_CBC>(input, verbose);
                break;

            case AES_CFB:
                decrypt_with_mode<algorithm, AES_CFB>(input, verbose);
                break;

            case AES_OFB:
                decrypt_with_mode<algorithm, AES_OFB>(input, verbose);
                break;

            case AES_CTR:
                decrypt_with_mode<algorithm, AES_CTR>(input, verbose);
                break;

            default:
                throw std::runtime_error("the selected mode of operation is not implemented");
                break;
        }
    }

    void decrypt_using_cxx_api(
        aes::Algorithm algorithm,
        aes::Mode mode,
        const Input& input,
        bool verbose = false)
    {
        switch (algorithm)
        {
            case AES_AES128:
                decrypt_with_algorithm<AES_AES128>(mode, input, verbose);
                break;

            case AES_AES192:
                decrypt_with_algorithm<AES_AES192>(mode, input, verbose);
                break;

            case AES_AES256:
                decrypt_with_algorithm<AES_AES256>(mode, input, verbose);
                break;

            default:
                throw std::runtime_error("the selected algorithm is not implemented");
                break;
        }
    }

    void decrypt_using_particular_box(
        aes::Box& box,
        const std::vector<std::string>& input_block_strings)
    {
        for (const auto& input_block_string : input_block_strings)
        {
            aes::Box::Block ciphertext;
            box.parse_block(ciphertext, input_block_string);

            aes::Box::Block plaintext;
            box.decrypt_block(ciphertext, plaintext);
            std::cout << box.format_block(plaintext) << '\n';
        }
    }

    void decrypt_using_boxes(
        aes::Algorithm algorithm,
        aes::Mode mode,
        const Input& input)
    {
        aes::Box::Key key;
        aes::Box::parse_key(key, algorithm, input.get_key_string());

        if (aes::mode_requires_init_vector(mode))
        {
            aes::Box::Block iv;
            aes::Box::parse_block(iv, algorithm, input.get_iv_string());
            aes::Box box{algorithm, key, mode, iv};

            decrypt_using_particular_box(box, input.get_input_block_strings());
        }
        else
        {
            aes::Box box{algorithm, key};
            decrypt_using_particular_box(box, input.get_input_block_strings());
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser{argv[0]};
        try
        {
            std::vector<Input> inputs;
            const auto settings = cmd_parser.parse(argc, argv, inputs);

            if (cmd_parser.exit_with_usage())
            {
                std::cout << cmd_parser;
                return 0;
            }

            for (const auto& input : inputs)
            {
                if (settings.use_boxes)
                {
                    decrypt_using_boxes(
                        settings.algorithm,
                        settings.mode,
                        input);
                }
                else
                {
                    decrypt_using_cxx_api(
                        settings.algorithm,
                        settings.mode,
                        input,
                        settings.verbose);
                }
            }
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

/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

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
    template <aesni::Algorithm algorithm, aesni::Mode mode>
    void encrypt_with_mode(
        const Input& input,
        bool verbose = false)
    {
        typename aesni::Types<algorithm>::Block iv;

        if (aesni::ModeRequiresInitializationVector<mode>::value)
        {
            aesni::from_string<algorithm>(iv, input.get_iv_string());
            if (verbose)
                dump_iv<algorithm>(iv);
        }

        typename aesni::Types<algorithm>::Key key;
        aesni::from_string<algorithm>(key, input.get_key_string());
        if (verbose)
            dump_key<algorithm>(key);

        aesni::EncryptWrapper<algorithm, mode> encrypt(key, iv);
        if (verbose)
            dump_wrapper<algorithm, mode>(encrypt);

        for (const auto& input_block_string : input.get_input_block_strings())
        {
            typename aesni::Types<algorithm>::Block plaintext, ciphertext;
            aesni::from_string<algorithm>(plaintext, input_block_string);

            encrypt.encrypt_block(plaintext, ciphertext);

            if (verbose)
            {
                dump_plaintext<algorithm>(plaintext);
                dump_ciphertext<algorithm>(ciphertext);
                dump_next_iv<algorithm, mode>(encrypt);
            }
            else
            {
                std::cout << aesni::to_string<algorithm>(ciphertext) << '\n';
            }
        }
    }

    template <aesni::Algorithm algorithm>
    void encrypt_with_algorithm(
        aesni::Mode mode,
        const Input& input,
        bool verbose = false)
    {
        switch (mode)
        {
            case AESNI_ECB:
                encrypt_with_mode<algorithm, AESNI_ECB>(input, verbose);
                break;

            case AESNI_CBC:
                encrypt_with_mode<algorithm, AESNI_CBC>(input, verbose);
                break;

            case AESNI_CFB:
                encrypt_with_mode<algorithm, AESNI_CFB>(input, verbose);
                break;

            case AESNI_OFB:
                encrypt_with_mode<algorithm, AESNI_OFB>(input, verbose);
                break;

            case AESNI_CTR:
                encrypt_with_mode<algorithm, AESNI_CTR>(input, verbose);
                break;

            default:
                throw std::runtime_error("the selected mode of operation is not implemented");
                break;
        }
    }

    void encrypt_using_cxx_api(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const Input& input,
        bool verbose = false)
    {
        switch (algorithm)
        {
            case AESNI_AES128:
                encrypt_with_algorithm<AESNI_AES128>(mode, input, verbose);
                break;

            case AESNI_AES192:
                encrypt_with_algorithm<AESNI_AES192>(mode, input, verbose);
                break;

            case AESNI_AES256:
                encrypt_with_algorithm<AESNI_AES256>(mode, input, verbose);
                break;

            default:
                throw std::runtime_error("the selected algorithm is not implemented");
                break;
        }
    }

    void encrypt_using_particular_box(
        aesni::Box& box,
        const std::vector<std::string>& input_block_strings)
    {
        for (const auto& input_block_string : input_block_strings)
        {
            aesni::Box::Block plaintext;
            box.parse_block(plaintext, input_block_string);

            aesni::Box::Block ciphertext;
            box.encrypt_block(plaintext, ciphertext);
            std::cout << box.format_block(ciphertext) << '\n';
        }
    }

    void encrypt_using_boxes(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const Input& input)
    {
        aesni::Box::Key key;
        aesni::Box::parse_key(key, algorithm, input.get_key_string());

        if (aesni::mode_requires_initialization_vector(mode))
        {
            aesni::Box::Block iv;
            aesni::Box::parse_block(iv, algorithm, input.get_iv_string());

            encrypt_using_particular_box(
                aesni::Box(algorithm, key, mode, iv), input.get_input_block_strings());
        }
        else
        {
            encrypt_using_particular_box(
                aesni::Box(algorithm, key), input.get_input_block_strings());
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
            std::vector<Input> inputs;
            Settings settings;
            cmd_parser.parse(settings, argc, argv, inputs);

            if (cmd_parser.exit_with_usage())
            {
                std::cout << cmd_parser;
                return 0;
            }

            for (const auto& input : inputs)
            {
                if (settings.use_boxes())
                {
                    encrypt_using_boxes(
                        settings.get_algorithm(),
                        settings.get_mode(),
                        input);
                }
                else
                {
                    encrypt_using_cxx_api(
                        settings.get_algorithm(),
                        settings.get_mode(),
                        input,
                        settings.verbose());
                }
            }

            return 0;
        }
        catch (const boost::program_options::error& e)
        {
            std::cerr << "Usage error: " << e.what() << "\n";
            std::cerr << cmd_parser;
            return 1;
        }
        catch (const aesni::Error& e)
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

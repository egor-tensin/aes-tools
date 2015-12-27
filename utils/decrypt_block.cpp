/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "block_cmd_parser.hpp"
#include "block_dumper.hpp"

#include <aesnixx/all.hpp>

#include <boost/program_options.hpp>

#include <exception>
#include <iostream>
#include <iterator>
#include <string>

namespace
{
    template <aesni::Algorithm algorithm, aesni::Mode mode>
    void decrypt_with_mode(
        const Input& input,
        bool verbose = false)
    {
        typename aesni::Types<algorithm>::Block iv;

        if (aesni::ModeRequiresInitializationVector<mode>())
        {
            aesni::from_string<algorithm>(iv, input.get_iv_string());
            if (verbose)
                dump_iv<algorithm>(iv);
        }

        typename aesni::Types<algorithm>::Key key;
        aesni::from_string<algorithm>(key, input.get_key_string());
        if (verbose)
            dump_key<algorithm>(key);

        aesni::DecryptWrapper<algorithm, mode> decrypt(key, iv);
        if (verbose)
            dump_wrapper<algorithm, mode>(decrypt);

        for (const auto& input_block_string : input.get_input_block_strings())
        {
            typename aesni::Types<algorithm>::Block ciphertext, plaintext;
            aesni::from_string<algorithm>(ciphertext, input_block_string);

            decrypt.decrypt_block(ciphertext, plaintext);

            if (verbose)
            {
                dump_ciphertext<algorithm>(ciphertext);
                dump_plaintext<algorithm>(plaintext);
                dump_next_iv<algorithm, mode>(decrypt);
            }
            else
            {
                std::cout << aesni::to_string<algorithm>(plaintext) << '\n';
            }
        }
    }

    template <aesni::Algorithm algorithm>
    void decrypt_with_algorithm(
        aesni::Mode mode,
        const Input& input,
        bool verbose = false)
    {
        switch (mode)
        {
            case AESNI_ECB:
                decrypt_with_mode<algorithm, AESNI_ECB>(input, verbose);
                break;

            case AESNI_CBC:
                decrypt_with_mode<algorithm, AESNI_CBC>(input, verbose);
                break;

            case AESNI_CFB:
                decrypt_with_mode<algorithm, AESNI_CFB>(input, verbose);
                break;

            case AESNI_OFB:
                decrypt_with_mode<algorithm, AESNI_OFB>(input, verbose);
                break;

            case AESNI_CTR:
                decrypt_with_mode<algorithm, AESNI_CTR>(input, verbose);
                break;

            default:
                throw_not_implemented(mode);
                break;
        }
    }

    void decrypt_using_cxx_api(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const Input& input,
        bool verbose = false)
    {
        switch (algorithm)
        {
            case AESNI_AES128:
                decrypt_with_algorithm<AESNI_AES128>(mode, input, verbose);
                break;

            case AESNI_AES192:
                decrypt_with_algorithm<AESNI_AES192>(mode, input, verbose);
                break;

            case AESNI_AES256:
                decrypt_with_algorithm<AESNI_AES256>(mode, input, verbose);
                break;

            default:
                throw_not_implemented(algorithm);
                break;
        }
    }

    void decrypt_using_particular_box(
        aesni::Box& box,
        const std::vector<std::string>& input_block_strings)
    {
        for (const auto& input_block_string : input_block_strings)
        {
            aesni::Box::Block ciphertext;
            box.parse_block(ciphertext, input_block_string);

            aesni::Box::Block plaintext;
            box.decrypt_block(ciphertext, plaintext);
            std::cout << box.format_block(plaintext) << '\n';
        }
    }

    void decrypt_using_boxes(
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

            decrypt_using_particular_box(
                aesni::Box(algorithm, key, mode, iv),
                input.get_input_block_strings());
        }
        else
        {
            decrypt_using_particular_box(
                aesni::Box(algorithm, key),
                input.get_input_block_strings());
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
            std::vector<Input> inputs;
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
                    decrypt_using_boxes(
                        settings.get_algorithm(),
                        settings.get_mode(),
                        input);
                }
                else
                {
                    decrypt_using_cxx_api(
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

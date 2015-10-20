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

#include <deque>
#include <exception>
#include <iostream>
#include <iterator>
#include <string>

namespace
{
    template <aesni::Algorithm algorithm, aesni::Mode mode>
    void decrypt_with_mode(
        const std::string& key_str,
        std::deque<std::string>& ciphertexts,
        bool verbose = false)
    {
        typename aesni::Types<algorithm>::Block iv;

        if (aesni::ModeRequiresInitializationVector<mode>())
        {
            if (ciphertexts.empty())
                throw_iv_required();

            aesni::from_string<algorithm>(iv, ciphertexts.front());
            ciphertexts.pop_front();

            if (verbose)
                dump_iv<algorithm>(iv);
        }

        typename aesni::Types<algorithm>::Key key;
        aesni::from_string<algorithm>(key, key_str);

        if (verbose)
            dump_key<algorithm>(key);

        aesni::DecryptWrapper<algorithm, mode> decrypt(key, iv);

        if (verbose)
            dump_wrapper<algorithm, mode>(decrypt);

        while (!ciphertexts.empty())
        {
            typename aesni::Types<algorithm>::Block ciphertext, plaintext;
            aesni::from_string<algorithm>(ciphertext, ciphertexts.front());
            ciphertexts.pop_front();

            decrypt.decrypt_block(ciphertext, plaintext);

            if (verbose)
            {
                dump_ciphertext<algorithm>(ciphertext);
                dump_plaintext<algorithm>(plaintext);
                dump_next_iv<algorithm, mode>(decrypt);
            }
            else
            {
                std::cout << aesni::to_string<algorithm>(plaintext) << "\n";
            }
        }
    }

    template <aesni::Algorithm algorithm>
    void decrypt_with_algorithm(
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& ciphertexts,
        bool verbose = false)
    {
        switch (mode)
        {
            case AESNI_ECB:
                decrypt_with_mode<algorithm, AESNI_ECB>(key_str, ciphertexts, verbose);
                break;

            case AESNI_CBC:
                decrypt_with_mode<algorithm, AESNI_CBC>(key_str, ciphertexts, verbose);
                break;

            case AESNI_CFB:
                decrypt_with_mode<algorithm, AESNI_CFB>(key_str, ciphertexts, verbose);
                break;

            case AESNI_OFB:
                decrypt_with_mode<algorithm, AESNI_OFB>(key_str, ciphertexts, verbose);
                break;

            case AESNI_CTR:
                decrypt_with_mode<algorithm, AESNI_CTR>(key_str, ciphertexts, verbose);
                break;

            default:
                throw_not_implemented(mode);
                break;
        }
    }

    void decrypt_using_cxx_api(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& ciphertexts,
        bool verbose = false)
    {
        switch (algorithm)
        {
            case AESNI_AES128:
                decrypt_with_algorithm<AESNI_AES128>(mode, key_str, ciphertexts, verbose);
                break;

            case AESNI_AES192:
                decrypt_with_algorithm<AESNI_AES192>(mode, key_str, ciphertexts, verbose);
                break;

            case AESNI_AES256:
                decrypt_with_algorithm<AESNI_AES256>(mode, key_str, ciphertexts, verbose);
                break;

            default:
                throw_not_implemented(algorithm);
                break;
        }
    }

    void decrypt_using_particular_box(
        aesni::Box& box,
        std::deque<std::string>& ciphertexts)
    {
        while (!ciphertexts.empty())
        {
            aesni::Box::Block ciphertext;
            box.parse_block(ciphertext, ciphertexts.front());
            ciphertexts.pop_front();

            aesni::Box::Block plaintext;
            box.decrypt_block(ciphertext, plaintext);

            std::cout << box.format_block(plaintext) << "\n";
        }
    }

    void decrypt_using_boxes(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& ciphertexts)
    {
        aesni::Box::Key key;
        aesni::Box::parse_key(key, algorithm, key_str);

        if (aesni::mode_requires_initialization_vector(mode))
        {
            if (ciphertexts.empty())
                throw_iv_required();

            aesni::Box::Block iv;
            aesni::Box::parse_block(iv, algorithm, ciphertexts.front());
            ciphertexts.pop_front();

            decrypt_using_particular_box(
                aesni::Box(algorithm, key, mode, iv), ciphertexts);
        }
        else
        {
            decrypt_using_particular_box(
                aesni::Box(algorithm, key), ciphertexts);
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser("decrypt_block.exe");
        try
        {
            cmd_parser.parse(argc, argv);

            if (cmd_parser.requested_help())
            {
                std::cout << cmd_parser;
                return 0;
            }

            std::deque<std::string> args(
                std::make_move_iterator(cmd_parser.args.begin()),
                std::make_move_iterator(cmd_parser.args.end()));

            while (!args.empty())
            {
                const auto key = args.front();
                args.pop_front();

                std::deque<std::string> ciphertexts;

                while (!args.empty())
                {
                    if (args.front() == "--")
                    {
                        args.pop_front();
                        break;
                    }

                    ciphertexts.push_back(args.front());
                    args.pop_front();
                }

                if (cmd_parser.use_boxes)
                {
                    decrypt_using_boxes(
                        cmd_parser.algorithm,
                        cmd_parser.mode,
                        key,
                        ciphertexts);
                }
                else
                {
                    decrypt_using_cxx_api(
                        cmd_parser.algorithm,
                        cmd_parser.mode,
                        key,
                        ciphertexts,
                        cmd_parser.verbose);
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

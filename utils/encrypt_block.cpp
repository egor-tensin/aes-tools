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
    void encrypt_with_mode(
        const std::string& key_str,
        std::deque<std::string>& plaintexts,
        bool verbose = false)
    {
        typename aesni::Types<algorithm>::Block iv;

        if (aesni::ModeRequiresInitializationVector<mode>::value)
        {
            if (plaintexts.empty())
                throw_iv_required();

            aesni::from_string<algorithm>(iv, plaintexts.front());
            plaintexts.pop_front();

            if (verbose)
                dump_iv<algorithm>(iv);
        }

        typename aesni::Types<algorithm>::Key key;
        aesni::from_string<algorithm>(key, key_str);

        if (verbose)
            dump_key<algorithm>(key);

        aesni::EncryptWrapper<algorithm, mode> encrypt(key, iv);

        if (verbose)
            dump_wrapper<algorithm, mode>(encrypt);

        while (!plaintexts.empty())
        {
            typename aesni::Types<algorithm>::Block plaintext, ciphertext;
            aesni::from_string<algorithm>(plaintext, plaintexts.front());
            plaintexts.pop_front();
            encrypt.encrypt_block(plaintext, ciphertext);

            if (verbose)
            {
                dump_plaintext<algorithm>(plaintext);
                dump_ciphertext<algorithm>(ciphertext);
                dump_next_iv<algorithm, mode>(encrypt);
            }
            else
            {
                std::cout << aesni::to_string<algorithm>(ciphertext) << "\n";
            }
        }
    }

    template <aesni::Algorithm algorithm>
    void encrypt_with_algorithm(
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& plaintexts,
        bool verbose = false)
    {
        switch (mode)
        {
            case AESNI_ECB:
                encrypt_with_mode<algorithm, AESNI_ECB>(key_str, plaintexts, verbose);
                break;

            case AESNI_CBC:
                encrypt_with_mode<algorithm, AESNI_CBC>(key_str, plaintexts, verbose);
                break;

            case AESNI_CFB:
                encrypt_with_mode<algorithm, AESNI_CFB>(key_str, plaintexts, verbose);
                break;

            case AESNI_OFB:
                encrypt_with_mode<algorithm, AESNI_OFB>(key_str, plaintexts, verbose);
                break;

            case AESNI_CTR:
                encrypt_with_mode<algorithm, AESNI_CTR>(key_str, plaintexts, verbose);
                break;

            default:
                throw_not_implemented(mode);
                break;
        }
    }

    void encrypt_using_cxx_api(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& plaintexts,
        bool verbose = false)
    {
        switch (algorithm)
        {
            case AESNI_AES128:
                encrypt_with_algorithm<AESNI_AES128>(mode, key_str, plaintexts, verbose);
                break;

            case AESNI_AES192:
                encrypt_with_algorithm<AESNI_AES192>(mode, key_str, plaintexts, verbose);
                break;

            case AESNI_AES256:
                encrypt_with_algorithm<AESNI_AES256>(mode, key_str, plaintexts, verbose);
                break;

            default:
                throw_not_implemented(algorithm);
                break;
        }
    }

    void encrypt_using_particular_box(
        aesni::Box& box,
        std::deque<std::string>& plaintexts)
    {
        while (!plaintexts.empty())
        {
            aesni::Box::Block plaintext;
            box.parse_block(
                plaintext, plaintexts.front());
            plaintexts.pop_front();

            aesni::Box::Block ciphertext;
            box.encrypt_block(plaintext, ciphertext);

            std::cout << box.format_block(ciphertext) << "\n";
        }
    }

    void encrypt_using_boxes(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& plaintexts)
    {
        aesni::Box::Key key;
        aesni::Box::parse_key(key, algorithm, key_str);

        if (aesni::mode_requires_initialization_vector(mode))
        {
            if (plaintexts.empty())
                throw_iv_required();

            aesni::Box::Block iv;
            aesni::Box::parse_block(iv, algorithm, plaintexts.front());
            plaintexts.pop_front();

            encrypt_using_particular_box(
                aesni::Box(algorithm, key, mode, iv), plaintexts);
        }
        else
        {
            encrypt_using_particular_box(
                aesni::Box(algorithm, key), plaintexts);
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser("encrypt_block.exe");
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

                std::deque<std::string> plaintexts;

                while (!args.empty())
                {
                    if (args.front() == "--")
                    {
                        args.pop_front();
                        break;
                    }

                    plaintexts.push_back(args.front());
                    args.pop_front();
                }

                if (cmd_parser.use_boxes)
                {
                    encrypt_using_boxes(
                        cmd_parser.algorithm,
                        cmd_parser.mode,
                        key,
                        plaintexts);
                }
                else
                {
                    encrypt_using_cxx_api(
                        cmd_parser.algorithm,
                        cmd_parser.mode,
                        key,
                        plaintexts,
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

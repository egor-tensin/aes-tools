/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "block_common.hpp"

#include <aesni/all.h>

#include <aesnixx/all.hpp>

#include <deque>
#include <exception>
#include <iostream>
#include <string>

namespace
{
    template <aesni::Algorithm algorithm, aesni::Mode mode>
    bool encrypt_with_mode(
        const std::string& key_str,
        std::deque<std::string>& plaintexts,
        bool verbose = false)
    {
        typename aesni::Types<algorithm>::Block iv;

        if (aesni::ModeRequiresInitializationVector<mode>::value)
        {
            if (plaintexts.empty())
                return false;

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

        return true;
    }

    template <aesni::Algorithm algorithm>
    bool encrypt_with_algorithm(
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& plaintexts,
        bool verbose = false)
    {
        switch (mode)
        {
            case AESNI_ECB:
                return encrypt_with_mode<algorithm, AESNI_ECB>(key_str, plaintexts, verbose);

            case AESNI_CBC:
                return encrypt_with_mode<algorithm, AESNI_CBC>(key_str, plaintexts, verbose);

            case AESNI_CFB:
                return encrypt_with_mode<algorithm, AESNI_CFB>(key_str, plaintexts, verbose);

            case AESNI_OFB:
                return encrypt_with_mode<algorithm, AESNI_OFB>(key_str, plaintexts, verbose);

            case AESNI_CTR:
                return encrypt_with_mode<algorithm, AESNI_CTR>(key_str, plaintexts, verbose);

            default:
                return false;
        }
    }

    bool encrypt_using_cxx_api(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& plaintexts,
        bool verbose = false)
    {
        switch (algorithm)
        {
            case AESNI_AES128:
                return encrypt_with_algorithm<AESNI_AES128>(mode, key_str, plaintexts, verbose);

            case AESNI_AES192:
                return encrypt_with_algorithm<AESNI_AES192>(mode, key_str, plaintexts, verbose);

            case AESNI_AES256:
                return encrypt_with_algorithm<AESNI_AES256>(mode, key_str, plaintexts, verbose);

            default:
                return false;
        }
    }

    template <aesni::Algorithm algorithm>
    bool encrypt_using_boxes_with_algorithm(
        const AesNI_BoxAlgorithmParams& algorithm_params,
        aesni::Mode mode,
        const std::string& key,
        std::deque<std::string> plaintexts)
    {
        AesNI_BoxBlock iv;
        AesNI_BoxBlock* iv_ptr = nullptr;

        if (aesni::mode_requires_initialization_vector(mode))
        {
            if (plaintexts.empty())
                return false;

            aesni::from_string<AESNI_AES128>(iv.aes_block, plaintexts.front());
            iv_ptr = &iv;
            plaintexts.pop_front();
        }

        AesNI_Box box;
        aesni_box_init(
            &box,
            algorithm,
            &algorithm_params,
            mode,
            iv_ptr,
            aesni::ErrorDetailsThrowsInDestructor());

        while (!plaintexts.empty())
        {
            AesNI_BoxBlock plaintext;
            aesni::from_string<algorithm>(plaintext.aes_block, plaintexts.front());
            plaintexts.pop_front();

            AesNI_BoxBlock ciphertext;
            aesni_box_encrypt_block(
                &box,
                &plaintext,
                &ciphertext,
                aesni::ErrorDetailsThrowsInDestructor());

            std::cout << aesni::to_string<algorithm>(ciphertext.aes_block) << "\n";
        }

        return true;
    }

    bool encrypt_using_boxes(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key,
        std::deque<std::string> plaintexts)
    {
        AesNI_BoxAlgorithmParams algorithm_params;

        switch (algorithm)
        {
            case AESNI_AES128:
                aesni::from_string<AESNI_AES128>(
                    algorithm_params.aes128_key, key);
                return encrypt_using_boxes_with_algorithm<AESNI_AES128>(
                    algorithm_params, mode, key, plaintexts);

            case AESNI_AES192:
                aesni::from_string<AESNI_AES192>(
                    algorithm_params.aes192_key, key);
                return encrypt_using_boxes_with_algorithm<AESNI_AES192>(
                    algorithm_params, mode, key, plaintexts);

            case AESNI_AES256:
                aesni::from_string<AESNI_AES256>(
                    algorithm_params.aes256_key, key);
                return encrypt_using_boxes_with_algorithm<AESNI_AES256>(
                    algorithm_params, mode, key, plaintexts);

            default:
                return false;
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser("encrypt_block.exe");

        if (!cmd_parser.parse_options(argc, argv))
            return 0;

        const auto algorithm = cmd_parser.get_algorithm();
        const auto mode = cmd_parser.get_mode();

        auto args = cmd_parser.get_args();

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

            const auto success = cmd_parser.use_boxes()
                ? encrypt_using_boxes(algorithm, mode, key, plaintexts)
                : encrypt_using_cxx_api(algorithm, mode, key, plaintexts, cmd_parser.verbose());

            if (!success)
            {
                cmd_parser.print_usage();
                return 1;
            }
        }

        return 0;
    }
    catch (const boost::program_options::error& e)
    {
        std::cerr << "Usage error: " << e.what() << "\n";
        return 1;
    }
    catch (const aesni::Error& e)
    {
        std::cerr << e;
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }
}

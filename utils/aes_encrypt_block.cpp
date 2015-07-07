/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "aes_block_common.hpp"

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
        std::deque<std::string>& plaintexts)
    {
        typename aesni::aes::Types<algorithm>::BlockT iv;

        if (aesni::ModeRequiresInitializationVector<mode>())
        {
            if (plaintexts.empty())
                return false;

            aesni::aes::from_string(iv, plaintexts.front());
            plaintexts.pop_front();
        }

        typename aesni::aes::Types<algorithm>::KeyT key;
        aesni::aes::from_string(key, key_str);

        aesni::aes::Encrypt<algorithm, mode> encrypt(key, iv);

        while (!plaintexts.empty())
        {
            typename aesni::aes::Types<algorithm>::BlockT plaintext;
            aesni::aes::from_string(plaintext, plaintexts.front());
            plaintexts.pop_front();

            std::cout << aesni::aes::to_string(encrypt.encrypt(plaintext)) << "\n";
        }

        return true;
    }

    template <aesni::Algorithm algorithm>
    bool encrypt_with_algorithm(
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& plaintexts)
    {
        switch (mode)
        {
            case AESNI_ECB:
                return encrypt_with_mode<algorithm, AESNI_ECB>(key_str, plaintexts);

            case AESNI_CBC:
                return encrypt_with_mode<algorithm, AESNI_CBC>(key_str, plaintexts);

            case AESNI_CFB:
                return encrypt_with_mode<algorithm, AESNI_CFB>(key_str, plaintexts);

            case AESNI_OFB:
                return encrypt_with_mode<algorithm, AESNI_OFB>(key_str, plaintexts);

            case AESNI_CTR:
                return encrypt_with_mode<algorithm, AESNI_CTR>(key_str, plaintexts);

            default:
                return false;
        }
    }

    bool encrypt(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string> plaintexts)
    {
        switch (algorithm)
        {
            case AESNI_AES128:
                return encrypt_with_algorithm<AESNI_AES128>(mode, key_str, plaintexts);

            case AESNI_AES192:
                return encrypt_with_algorithm<AESNI_AES192>(mode, key_str, plaintexts);

            case AESNI_AES256:
                return encrypt_with_algorithm<AESNI_AES256>(mode, key_str, plaintexts);

            default:
                return false;
        }
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
                aesni::aes::from_string(algorithm_params.aes128_key, key);
                break;

            case AESNI_AES192:
                aesni::aes::from_string(algorithm_params.aes192_key, key);
                break;

            case AESNI_AES256:
                aesni::aes::from_string(algorithm_params.aes256_key, key);
                break;

            default:
                return false;
        }

        AesNI_BoxBlock iv;
        AesNI_BoxBlock* iv_ptr = nullptr;

        if (aesni::mode_requires_initialization_vector(mode))
        {
            if (plaintexts.empty())
                return false;

            aesni::aes::from_string(iv.aes_block, plaintexts.front());
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
            aesni::aes::from_string(plaintext.aes_block, plaintexts.front());
            plaintexts.pop_front();

            AesNI_BoxBlock ciphertext;
            aesni_box_encrypt_block(
                &box,
                &plaintext,
                &ciphertext,
                aesni::ErrorDetailsThrowsInDestructor());

            std::cout << aesni::aes::to_string(ciphertext.aes_block) << "\n";
        }

        return true;
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser("aes_encrypt_block.exe");

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
                : encrypt(algorithm, mode, key, plaintexts);

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

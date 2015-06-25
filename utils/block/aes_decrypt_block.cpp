/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "aes_common.hpp"

#include <aesni/all.h>

#include <aesnixx/all.hpp>

#include <deque>
#include <exception>
#include <iostream>
#include <string>

namespace
{
    template <aesni::Algorithm algorithm, aesni::Mode mode>
    bool decrypt_with_mode(
        const std::string& key_str,
        std::deque<std::string>& ciphertexts)
    {
        typename aesni::aes::Types<algorithm>::BlockT iv;

        if (aesni::ModeRequiresInitializationVector<mode>())
        {
            if (ciphertexts.empty())
                return false;

            aesni::aes::from_string(iv, ciphertexts.front());
            ciphertexts.pop_front();
        }

        typename aesni::aes::Types<algorithm>::KeyT key;
        aesni::aes::from_string(key, key_str);

        aesni::aes::Encrypt<algorithm, mode> encrypt(key, iv);

        while (!ciphertexts.empty())
        {
            typename aesni::aes::Types<algorithm>::BlockT ciphertext;
            aesni::aes::from_string(ciphertext, ciphertexts.front());
            ciphertexts.pop_front();

            std::cout << aesni::aes::to_string(encrypt.decrypt(ciphertext)) << "\n";
        }

        return true;
    }

    template <aesni::Algorithm algorithm>
    bool decrypt_with_algorithm(
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& ciphertexts)
    {
        switch (mode)
        {
            case AESNI_ECB:
                return decrypt_with_mode<algorithm, AESNI_ECB>(key_str, ciphertexts);

            case AESNI_CBC:
                return decrypt_with_mode<algorithm, AESNI_CBC>(key_str, ciphertexts);

            case AESNI_CFB:
                return decrypt_with_mode<algorithm, AESNI_CFB>(key_str, ciphertexts);

            case AESNI_OFB:
                return decrypt_with_mode<algorithm, AESNI_OFB>(key_str, ciphertexts);

            case AESNI_CTR:
                return decrypt_with_mode<algorithm, AESNI_CTR>(key_str, ciphertexts);

            default:
                return false;
        }
    }

    bool decrypt(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string> ciphertexts)
    {
        switch (algorithm)
        {
            case AESNI_AES128:
                return decrypt_with_algorithm<AESNI_AES128>(mode, key_str, ciphertexts);

            case AESNI_AES192:
                return decrypt_with_algorithm<AESNI_AES192>(mode, key_str, ciphertexts);

            case AESNI_AES256:
                return decrypt_with_algorithm<AESNI_AES256>(mode, key_str, ciphertexts);

            default:
                return false;
        }
    }

    bool decrypt_using_boxes(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key,
        std::deque<std::string> ciphertexts)
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
            if (ciphertexts.empty())
                return false;

            aesni::aes::from_string(iv.aes_block, ciphertexts.front());
            iv_ptr = &iv;
            ciphertexts.pop_front();
        }

        AesNI_Box box;
        aesni_box_init(
            &box,
            algorithm,
            &algorithm_params,
            mode,
            iv_ptr,
            aesni::ErrorDetailsThrowsInDestructor());

        while (!ciphertexts.empty())
        {
            AesNI_BoxBlock ciphertext;
            aesni::aes::from_string(ciphertext.aes_block, ciphertexts.front());
            ciphertexts.pop_front();

            AesNI_BoxBlock plaintext;
            aesni_box_decrypt_block(
                &box,
                &ciphertext,
                &plaintext,
                aesni::ErrorDetailsThrowsInDestructor());

            std::cout << aesni::aes::to_string(plaintext.aes_block) << "\n";
        }

        return true;
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser("aes_decrypt_block.exe");

        if (!cmd_parser.parse_options(argc, argv))
            return 0;

        const auto algorithm = cmd_parser.get_algorithm();
        const auto mode = cmd_parser.get_mode();

        auto args = cmd_parser.get_args();

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

            const auto success = cmd_parser.use_boxes()
                ? decrypt_using_boxes(algorithm, mode, key, ciphertexts)
                : decrypt(algorithm, mode, key, ciphertexts);

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

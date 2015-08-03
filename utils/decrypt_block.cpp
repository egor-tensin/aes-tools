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
    bool decrypt_with_mode(
        const std::string& key_str,
        std::deque<std::string>& ciphertexts,
        bool verbose = false)
    {
        typename aesni::Types<algorithm>::Block iv;

        if (aesni::ModeRequiresInitializationVector<mode>())
        {
            if (ciphertexts.empty())
                return false;

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

        return true;
    }

    template <aesni::Algorithm algorithm>
    bool decrypt_with_algorithm(
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string>& ciphertexts,
        bool verbose = false)
    {
        switch (mode)
        {
            case AESNI_ECB:
                return decrypt_with_mode<algorithm, AESNI_ECB>(key_str, ciphertexts, verbose);

            case AESNI_CBC:
                return decrypt_with_mode<algorithm, AESNI_CBC>(key_str, ciphertexts, verbose);

            case AESNI_CFB:
                return decrypt_with_mode<algorithm, AESNI_CFB>(key_str, ciphertexts, verbose);

            case AESNI_OFB:
                return decrypt_with_mode<algorithm, AESNI_OFB>(key_str, ciphertexts, verbose);

            case AESNI_CTR:
                return decrypt_with_mode<algorithm, AESNI_CTR>(key_str, ciphertexts, verbose);

            default:
                return false;
        }
    }

    bool decrypt_using_cxx_api(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        const std::string& key_str,
        std::deque<std::string> ciphertexts,
        bool verbose = false)
    {
        switch (algorithm)
        {
            case AESNI_AES128:
                return decrypt_with_algorithm<AESNI_AES128>(mode, key_str, ciphertexts, verbose);

            case AESNI_AES192:
                return decrypt_with_algorithm<AESNI_AES192>(mode, key_str, ciphertexts, verbose);

            case AESNI_AES256:
                return decrypt_with_algorithm<AESNI_AES256>(mode, key_str, ciphertexts, verbose);

            default:
                return false;
        }
    }

    template <aesni::Algorithm algorithm>
    bool decrypt_using_boxes_with_algorithm(
        const AesNI_BoxAlgorithmParams& algorithm_params,
        aesni::Mode mode,
        const std::string& key,
        std::deque<std::string> ciphertexts)
    {
        AesNI_BoxBlock iv;
        AesNI_BoxBlock* iv_ptr = nullptr;

        if (aesni::mode_requires_initialization_vector(mode))
        {
            if (ciphertexts.empty())
                return false;

            aesni::from_string<algorithm>(iv.aes_block, ciphertexts.front());
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
            aesni::from_string<algorithm>(ciphertext.aes_block, ciphertexts.front());
            ciphertexts.pop_front();

            AesNI_BoxBlock plaintext;
            aesni_box_decrypt_block(
                &box,
                &ciphertext,
                &plaintext,
                aesni::ErrorDetailsThrowsInDestructor());

            std::cout << aesni::to_string<algorithm>(plaintext.aes_block) << "\n";
        }

        return true;
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
                aesni::from_string<AESNI_AES128>(
                    algorithm_params.aes128_key, key);
                return decrypt_using_boxes_with_algorithm<AESNI_AES128>(
                    algorithm_params, mode, key, ciphertexts);

            case AESNI_AES192:
                aesni::from_string<AESNI_AES192>(
                    algorithm_params.aes192_key, key);
                return decrypt_using_boxes_with_algorithm<AESNI_AES192>(
                    algorithm_params, mode, key, ciphertexts);

            case AESNI_AES256:
                aesni::from_string<AESNI_AES256>(
                    algorithm_params.aes256_key, key);
                return decrypt_using_boxes_with_algorithm<AESNI_AES256>(
                    algorithm_params, mode, key, ciphertexts);

            default:
                return false;
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser("decrypt_block.exe");

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
                : decrypt_using_cxx_api(algorithm, mode, key, ciphertexts, cmd_parser.verbose());

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

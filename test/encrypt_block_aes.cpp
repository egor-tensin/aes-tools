/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "common_aes.hpp"

#include <aesni/all.h>

#include <aesnixx/all.hpp>

#include <exception>
#include <iostream>

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser("encrypt_block_aes.exe");

        if (!cmd_parser.parse_options(argc, argv))
            return 0;

        auto args = cmd_parser.get_args();

        while (!args.empty())
        {
            AesNI_BoxAlgorithmParams algorithm_params;

            switch (cmd_parser.get_algorithm())
            {
                case AESNI_AES128:
                    aesni::aes::from_string(algorithm_params.aes128_key, args.front());
                    break;

                case AESNI_AES192:
                    aesni::aes::from_string(algorithm_params.aes192_key, args.front());
                    break;

                case AESNI_AES256:
                    aesni::aes::from_string(algorithm_params.aes256_key, args.front());
                    break;
            }

            args.pop_front();

            AesNI_BoxBlock iv;
            AesNI_BoxBlock* iv_ptr = nullptr;

            switch (cmd_parser.get_mode())
            {
                case AESNI_ECB:
                    break;

                case AESNI_CBC:
                case AESNI_CFB:
                case AESNI_OFB:
                case AESNI_CTR:
                    if (args.empty())
                    {
                        cmd_parser.print_usage();
                        return 1;
                    }
                    aesni::aes::from_string(iv.aes_block, args.front());
                    iv_ptr = &iv;
                    args.pop_front();
                    break;
            }

            AesNI_Box box;
            aesni_box_init(
                &box,
                cmd_parser.get_algorithm(),
                &algorithm_params,
                cmd_parser.get_mode(),
                iv_ptr,
                aesni::ErrorDetailsThrowsInDestructor());

            while (!args.empty())
            {
                if (args.front() == "--")
                {
                    args.pop_front();
                    break;
                }

                AesNI_BoxBlock plaintext;
                aesni::aes::from_string(plaintext.aes_block, args.front());
                args.pop_front();

                AesNI_BoxBlock ciphertext;
                aesni_box_encrypt_block(
                    &box,
                    &plaintext,
                    &ciphertext,
                    aesni::ErrorDetailsThrowsInDestructor());

                std::cout << aesni::aes::to_string(ciphertext.aes_block) << "\n";
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

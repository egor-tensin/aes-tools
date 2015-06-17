/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <aesnixx/all.hpp>

#include <cstdlib>
#include <cstring>

#include <exception>
#include <iostream>

namespace
{
    void exit_with_usage()
    {
        std::cout << "Usage: encrypt_block_aes.exe KEY0 IV0 [PLAIN0...] [-- KEY1 IV1 [PLAIN1...]...]\n";
        std::exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv)
{
    try
    {
        for (--argc, ++argv; argc > -1; --argc, ++argv)
        {
            if (argc < 2)
                exit_with_usage();

            AesNI_BoxAlgorithmParams algorithm_params;
            aesni::from_string(algorithm_params.aes128_key, argv[0]);

            AesNI_BoxBlock iv;
            aesni::from_string(iv.aes_block, argv[1]);

            AesNI_Box box;
            aesni_box_init(
                &box,
                AESNI_AES128,
                &algorithm_params,
                AESNI_OFB,
                &iv,
                aesni::ErrorDetailsThrowsInDestructor());

            for (argc -= 2, argv += 2; argc > 0; --argc, ++argv)
            {
                if (std::strcmp("--", argv[0]) == 0)
                    break;

                AesNI_BoxBlock ciphertext;
                aesni::from_string(ciphertext.aes_block, argv[0]);

                AesNI_BoxBlock plaintext;
                aesni_box_decrypt(
                    &box,
                    &ciphertext,
                    &plaintext,
                    aesni::ErrorDetailsThrowsInDestructor());

                std::cout << plaintext.aes_block << "\n";
            }
        }

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }
}

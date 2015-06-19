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

#include <exception>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

namespace
{
    void exit_with_usage()
    {
        std::cout << "Usage: aes128ecb_encrypt_file.exe KEY SRC DEST\n";
        std::exit(EXIT_FAILURE);
    }

    std::ifstream::pos_type get_file_size(const std::string& path)
    {
        std::ifstream ifs;
        ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ifs.open(path, std::ifstream::binary | std::ifstream::ate);
        return ifs.tellg();
    }
}

int main(int argc, char** argv)
{
    if (argc != 4)
        exit_with_usage();

    try
    {
        aesni::aes::Key128 key;
        aesni::aes::from_string(key, argv[1]);

        AesNI_Aes128_RoundKeys encryption_keys;

        const std::string src_path(argv[2]);
        const std::string dest_path(argv[3]);

        const auto src_size = static_cast<std::size_t>(get_file_size(src_path));

        std::ifstream src_ifs;
        src_ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        src_ifs.open(src_path, std::ifstream::binary);

        std::vector<char> src_buf;
        src_buf.reserve(src_size);
        src_buf.assign(std::istreambuf_iterator<char>(src_ifs),
                       std::istreambuf_iterator<char>());

        aesni_aes128_expand_key(&key, &encryption_keys);

        std::size_t dest_size;

        aesni_encrypt_buffer_ecb128(
            src_buf.data(),
            src_size,
            NULL,
            &dest_size,
            &encryption_keys,
            aesni::ErrorDetailsThrowsInDestructor());

        std::vector<char> dest_buf;
        dest_buf.reserve(dest_size);

        aesni_encrypt_buffer_ecb128(
            src_buf.data(),
            src_size,
            dest_buf.data(),
            &dest_size,
            &encryption_keys,
            aesni::ErrorDetailsThrowsInDestructor());

        std::ofstream dest_ofs;
        dest_ofs.exceptions(std::ofstream::badbit | std::ofstream::failbit);
        dest_ofs.open(dest_path, std::ofstream::binary);
        dest_ofs.write(dest_buf.data(), dest_size);
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

    return 0;
}

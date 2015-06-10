/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

extern "C"
{
#include <aesni/all.h>
}

#include <cstdio>

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
        std::ifstream ifs(path, std::ifstream::binary | std::ifstream::ate);
        return ifs.tellg();
    }
}

int main(int argc, char** argv)
{
    AesBlock128 key;
    Aes128KeySchedule key_schedule;

    if (argc != 4)
        exit_with_usage();

    if (parse_aes_block128(&key, argv[1]) != 0)
    {
        std::cerr << "Invalid 128-bit AES block '" << argv[1] << "'\n";
        exit_with_usage();
    }

    try
    {
        const std::string src_path(argv[2]);
        const std::string dest_path(argv[3]);

        const auto src_size = get_file_size(src_path);

        std::ifstream src_ifs;
        src_ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        src_ifs.open(src_path, std::ifstream::binary);

        std::vector<unsigned char> src_buf;
        src_buf.reserve(static_cast<std::vector<char>::size_type>(src_size));
        src_buf.assign(std::istreambuf_iterator<char>(src_ifs),
                       std::istreambuf_iterator<char>());

        aes128_expand_key_schedule(key, &key_schedule);

        const auto dest_size = aes128ecb_encrypt_buffer(
            src_buf.data(),
            static_cast<std::size_t>(src_size),
            NULL,
            &key_schedule);

        std::vector<unsigned char> dest_buf(static_cast<std::vector<char>::size_type>(dest_size));

        aes128ecb_encrypt_buffer(
            src_buf.data(),
            static_cast<std::size_t>(src_size),
            dest_buf.data(),
            &key_schedule);

        std::ofstream dest_ofs;
        dest_ofs.exceptions(std::ofstream::badbit | std::ofstream::failbit);
        dest_ofs.open(dest_path, std::ofstream::binary);
        dest_ofs.write(reinterpret_cast<const char*>(dest_buf.data()), dest_buf.size());
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}

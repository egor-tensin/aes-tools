/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "file_cmd_parser.hpp"

#include <aesni/all.h>

#include <aesnixx/all.hpp>

#include <boost/program_options.hpp>

#include <cstdlib>
#include <cstring>

#include <deque>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include <Windows.h>

namespace
{
    std::ifstream::pos_type get_file_size(const std::string& path)
    {
        std::ifstream ifs;
        ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ifs.open(path, std::ifstream::binary | std::ifstream::ate);
        return ifs.tellg();
    }

    std::vector<char> read_file(const std::string& path)
    {
        const auto size = static_cast<std::size_t>(get_file_size(path));

        std::ifstream ifs;
        ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ifs.open(path, std::ifstream::binary);

        std::vector<char> src_buf;
        src_buf.reserve(size);
        src_buf.assign(std::istreambuf_iterator<char>(ifs),
                       std::istreambuf_iterator<char>());
        return src_buf;
    }

    void write_file(const std::string& path, const std::vector<char>& src)
    {
        std::ofstream ofs;
        ofs.exceptions(std::ofstream::badbit | std::ofstream::failbit);
        ofs.open(path, std::ofstream::binary);
        ofs.write(src.data(), src.size());
    }

    template <aesni::Algorithm algorithm>
    bool decrypt_bmp_with_algorithm(
        const AesNI_BoxAlgorithmParams& algorithm_params,
        aesni::Mode mode,
        std::deque<std::string>& args)
    {
        AesNI_BoxBlock iv;
        AesNI_BoxBlock* iv_ptr = nullptr;

        if (aesni::mode_requires_initialization_vector(mode))
        {
            if (args.empty())
                return false;

            aesni::from_string<algorithm>(iv.aes_block, args.front());
            iv_ptr = &iv;
            args.pop_front();
        }

        if (args.size() != 2)
            return false;

        const auto src_path = args[0];
        const auto dest_path = args[1];

        const auto src_buf = read_file(src_path);

        const auto bmp_header = reinterpret_cast<const BITMAPFILEHEADER*>(src_buf.data());

        const auto header_size = bmp_header->bfOffBits;
        const auto cipherpixels = src_buf.data() + header_size;
        const auto cipherpixels_size = src_buf.size() - header_size;

        AesNI_Box box;

        aesni_box_init(
            &box,
            algorithm,
            &algorithm_params,
            mode,
            iv_ptr,
            aesni::ErrorDetailsThrowsInDestructor());

        std::size_t pixels_size;

        aesni_box_decrypt_buffer(
            &box,
            cipherpixels,
            cipherpixels_size,
            nullptr,
            &pixels_size,
            aesni::ErrorDetailsThrowsInDestructor());

        std::vector<char> dest_buf;
        dest_buf.resize(header_size + pixels_size);
        std::memcpy(dest_buf.data(), src_buf.data(), header_size);

        aesni_box_decrypt_buffer(
            &box,
            cipherpixels,
            cipherpixels_size,
            dest_buf.data() + header_size,
            &pixels_size,
            aesni::ErrorDetailsThrowsInDestructor());

        dest_buf.resize(header_size + pixels_size);
        write_file(dest_path, dest_buf);

        return true;
    }

    bool decrypt_bmp(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        std::deque<std::string>& args)
    {
        if (args.empty())
            return false;

        AesNI_BoxAlgorithmParams algorithm_params;

        switch (algorithm)
        {
            case AESNI_AES128:
                aesni::from_string<AESNI_AES128>(
                    algorithm_params.aes128_key, args.front());
                args.pop_front();
                return decrypt_bmp_with_algorithm<AESNI_AES128>(
                    algorithm_params, mode, args);

            case AESNI_AES192:
                aesni::from_string<AESNI_AES192>(
                    algorithm_params.aes192_key, args.front());
                args.pop_front();
                return decrypt_bmp_with_algorithm<AESNI_AES192>(
                    algorithm_params, mode, args);

            case AESNI_AES256:
                aesni::from_string<AESNI_AES256>(
                    algorithm_params.aes256_key, args.front());
                args.pop_front();
                return decrypt_bmp_with_algorithm<AESNI_AES256>(
                    algorithm_params, mode, args);

            default:
                return false;
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser("decrypt_bmp.exe");
        cmd_parser.parse(argc, argv);

        if (cmd_parser.requested_help())
        {
            std::cout << cmd_parser;
            return 0;
        }

        std::deque<std::string> args{ std::make_move_iterator(cmd_parser.args.begin()),
                                      std::make_move_iterator(cmd_parser.args.end()) };

        if (!decrypt_bmp(cmd_parser.algorithm, cmd_parser.mode, args))
        {
            std::cout << cmd_parser;
            return 1;
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

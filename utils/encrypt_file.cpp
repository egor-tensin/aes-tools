/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "file_common.hpp"

#include <aesni/all.h>

#include <aesnixx/all.hpp>

#include <boost/program_options.hpp>

#include <cstdlib>

#include <deque>
#include <exception>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

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
    bool encrypt_file_with_algorithm(
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
            return true;

        const auto src_path = args[0];
        const auto dest_path = args[1];

        const auto src_buf = read_file(src_path);

        AesNI_Box box;

        aesni_box_init(
            &box,
            algorithm,
            &algorithm_params,
            mode,
            iv_ptr,
            aesni::ErrorDetailsThrowsInDestructor());

        std::size_t dest_size;

        aesni_box_encrypt_buffer(
            &box,
            src_buf.data(),
            src_buf.size(),
            nullptr,
            &dest_size,
            aesni::ErrorDetailsThrowsInDestructor());

        std::vector<char> dest_buf;
        dest_buf.resize(dest_size);

        aesni_box_encrypt_buffer(
            &box,
            src_buf.data(),
            src_buf.size(),
            dest_buf.data(),
            &dest_size,
            aesni::ErrorDetailsThrowsInDestructor());

        dest_buf.resize(dest_size);
        write_file(dest_path, dest_buf);

        return true;
    }

    bool encrypt_file(
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
                return encrypt_file_with_algorithm<AESNI_AES128>(
                    algorithm_params, mode, args);

            case AESNI_AES192:
                aesni::from_string<AESNI_AES192>(
                    algorithm_params.aes192_key, args.front());
                args.pop_front();
                return encrypt_file_with_algorithm<AESNI_AES192>(
                    algorithm_params, mode, args);

            case AESNI_AES256:
                aesni::from_string<AESNI_AES256>(
                    algorithm_params.aes256_key, args.front());
                args.pop_front();
                return encrypt_file_with_algorithm<AESNI_AES256>(
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
        CommandLineParser cmd_parser("encrypt_file.exe");

        if (!cmd_parser.parse_options(argc, argv))
            return 0;

        if (!encrypt_file(cmd_parser.get_algorithm(), cmd_parser.get_mode(), cmd_parser.get_args()))
        {
            cmd_parser.print_usage();
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

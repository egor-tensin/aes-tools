/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "file_cmd_parser.hpp"

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
        src_buf.assign(
            std::istreambuf_iterator<char>(ifs),
            std::istreambuf_iterator<char>());
        return src_buf;
    }

    void write_file(
        const std::string& path,
        const std::vector<unsigned char>& src)
    {
        std::ofstream ofs;
        ofs.exceptions(std::ofstream::badbit | std::ofstream::failbit);
        ofs.open(path, std::ofstream::binary);
        ofs.write(reinterpret_cast<const char*>(src.data()), src.size());
    }

    void decrypt_bmp(
        aesni::Box& box,
        std::deque<std::string>& args)
    {
        if (args.empty())
            throw_src_path_required();
        const auto src_path = args.front();
        args.pop_front();

        if (args.empty())
            throw_dest_path_required();
        const auto dest_path = args.front();
        args.pop_front();

        const auto src_buf = read_file(src_path);

        const auto bmp_header = reinterpret_cast<const BITMAPFILEHEADER*>(src_buf.data());

        const auto header_size = bmp_header->bfOffBits;
        const auto cipherpixels = src_buf.data() + header_size;
        const auto cipherpixels_size = src_buf.size() - header_size;

        const auto pixels = box.decrypt_buffer(
            cipherpixels, cipherpixels_size);

        std::vector<unsigned char> dest_buf(header_size + pixels.size());
        std::memcpy(&dest_buf[0], bmp_header, header_size);
        std::memcpy(&dest_buf[0] + header_size, pixels.data(), pixels.size());

        write_file(dest_path, dest_buf);
    }

    void decrypt_bmp(
        aesni::Algorithm algorithm,
        aesni::Mode mode,
        std::deque<std::string>& args)
    {
        if (args.empty())
            throw_key_required();

        aesni::Box::Key key;
        aesni::Box::parse_key(key, algorithm, args.front());
        args.pop_front();

        if (aesni::mode_requires_initialization_vector(mode))
        {
            if (args.empty())
                throw_iv_required();

            aesni::Box::Block iv;
            aesni::Box::parse_block(iv, algorithm, args.front());
            args.pop_front();

            decrypt_bmp(
                aesni::Box(algorithm, key, mode, iv), args);
        }
        else
        {
            decrypt_bmp(
                aesni::Box(algorithm, key), args);
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        CommandLineParser cmd_parser(argv[0]);
        try
        {
            cmd_parser.parse(argc, argv);

            if (cmd_parser.requested_help())
            {
                std::cout << cmd_parser;
                return 0;
            }

            std::deque<std::string> args(
                std::make_move_iterator(cmd_parser.args.begin()),
                std::make_move_iterator(cmd_parser.args.end()));

            decrypt_bmp(cmd_parser.algorithm, cmd_parser.mode, args);
        }
        catch (const boost::program_options::error& e)
        {
            std::cerr << "Usage error: " << e.what() << "\n";
            std::cerr << cmd_parser;
            return 1;
        }
        catch (const aesni::Error& e)
        {
            std::cerr << e;
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }
    return 0;
}

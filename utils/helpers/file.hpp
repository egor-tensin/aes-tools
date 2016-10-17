// Copyright (c) 2016 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#include <cassert>
#include <cstddef>

#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

namespace file
{
    inline std::size_t get_file_size(const std::string& path)
    {
        std::ifstream ifs;
        ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ifs.open(path, std::ifstream::binary | std::ifstream::ate);
        const auto size = static_cast<std::streamoff>(ifs.tellg());
        assert(size <= static_cast<std::streamoff>(std::numeric_limits<std::size_t>::max()));
        return static_cast<std::size_t>(size);
    }

    inline std::vector<char> read_file(const std::string& path)
    {
        const auto size = get_file_size(path);

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

    inline void write_file(
        const std::string& path,
        const void* buffer,
        const std::size_t size)
    {
        std::ofstream ofs;
        ofs.exceptions(std::ofstream::badbit | std::ofstream::failbit);
        ofs.open(path, std::ofstream::binary);
        ofs.write(reinterpret_cast<const char*>(buffer), size);
    }

    inline void write_file(
        const std::string& path,
        const std::vector<unsigned char>& src)
    {
        write_file(path, src.data(), src.size());
    }
}

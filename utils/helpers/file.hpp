// Copyright (c) 2016 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#include <cstddef>

#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace file
{
    inline std::size_t cast_to_size_t(std::streamoff size)
    {
        if (size < 0)
            throw std::range_error{"file::cast_to_size_t: something went really wrong"};
        typedef std::make_unsigned<std::streamoff>::type unsigned_streamoff;
        if (static_cast<unsigned_streamoff>(size) > std::numeric_limits<std::size_t>::max())
            throw std::range_error{"file::cast_to_size_t: this file is too large"};
        return static_cast<std::size_t>(size);
    }

    inline std::size_t get_file_size(const std::string& path)
    {
        std::ifstream ifs;
        ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ifs.open(path, std::ifstream::binary | std::ifstream::ate);
        return cast_to_size_t(ifs.tellg());
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
            std::istreambuf_iterator<char>{ifs},
            std::istreambuf_iterator<char>{});
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

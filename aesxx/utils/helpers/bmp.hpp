// Copyright (c) 2016 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#include <windows.h>

#include <cstddef>
#include <cstring>

#include <string>
#include <utility>
#include <vector>

namespace bmp
{
    class BmpFile
    {
    public:
        BmpFile(std::vector<char>&& buffer)
            : buffer{std::move(buffer)}
            , header_size{extract_pixels_offset()}
        { }

        const void* get_buffer() const { return buffer.data(); }

        std::size_t get_size() const { return buffer.size(); }

        std::size_t get_header_size() const { return header_size; }

        const void* get_pixels() const
        {
            return buffer.data() + get_header_size();
        }

        std::size_t get_pixels_size() const
        {
            return get_size() - get_header_size();
        }

        void replace_pixels(std::vector<unsigned char>&& pixels)
        {
            buffer.resize(get_header_size() + pixels.size());
            std::memcpy(buffer.data() + get_header_size(), pixels.data(), pixels.size());
        }

    private:
        std::size_t extract_pixels_offset() const
        {
            const auto header = reinterpret_cast<const BITMAPFILEHEADER*>(get_buffer());
            return header->bfOffBits;
        }

        std::vector<char> buffer;
        std::size_t header_size;
    };
}

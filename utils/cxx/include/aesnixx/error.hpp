/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <aesni/all.h>

#include <cstdlib>

#include <stdexcept>
#include <string>
#include <vector>

namespace aesni
{
    class ErrorDetailsThrowsInDestructor
    {
    public:
        ErrorDetailsThrowsInDestructor()
        {
            aesni_make_error_success(get());
        }

        ~ErrorDetailsThrowsInDestructor()
        {
            if (aesni_get_error_code(get()) != AESNI_ERROR_SUCCESS)
            {
                std::vector<char> msg;
                msg.resize(aesni_format_error(get(), NULL, 0));
                aesni_format_error(get(), msg.data(), msg.size());
                throw std::runtime_error(std::string(msg.begin(), msg.end()));
            }
        }

        AesNI_ErrorDetails* get() { return &m_impl; }

        operator AesNI_ErrorDetails*() { return get(); }

    private:
        AesNI_ErrorDetails m_impl;
    };
}

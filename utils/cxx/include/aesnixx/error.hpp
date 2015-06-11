/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <aesni/all.h>

#include <stdexcept>

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
            if (m_impl.ec != AESNI_ERROR_SUCCESS)
                throw std::runtime_error(aesni_strerror(m_impl.ec));
        }

        AesNI_ErrorDetails* get() { return &m_impl; }

        operator AesNI_ErrorDetails*() { return get(); }

    private:
        AesNI_ErrorDetails m_impl;
    };
}

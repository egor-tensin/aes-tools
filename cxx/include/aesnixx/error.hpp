/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include "debug.hpp"

#include <aesni/all.h>

#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <functional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace aesni
{
    class Error : public std::runtime_error
    {
    public:
        Error(const AesNI_ErrorDetails& err_details)
            : std::runtime_error(format_error_message(err_details))
        {
            copy_call_stack(err_details);
        }

        void for_each_in_call_stack(const std::function<void (void*, const std::string&)>& callback) const
        {
            aux::CallStackFormatter formatter;
            std::for_each(m_call_stack, m_call_stack + m_call_stack_size, [&formatter, &callback] (void* addr)
            {
                callback(addr, formatter.format(addr));
            });
        }

    private:
        static std::string format_error_message(const AesNI_ErrorDetails& err_details)
        {
            std::vector<char> buf;
            buf.resize(aesni_format_error(&err_details, NULL, 0));
            aesni_format_error(&err_details, buf.data(), buf.size());
            return { buf.begin(), buf.end() };
        }

        void copy_call_stack(const AesNI_ErrorDetails& err_details)
        {
            m_call_stack_size = err_details.call_stack_size;
            std::memcpy(m_call_stack, err_details.call_stack, m_call_stack_size * sizeof(void*));
        }

        void* m_call_stack[AESNI_MAX_CALL_STACK_LENGTH];
        std::size_t m_call_stack_size;
    };

    std::ostream& operator<<(std::ostream& os, const Error& e)
    {
        os << "AesNI error: " << e.what() << '\n';
        os << "Call stack:\n";
        e.for_each_in_call_stack([&os] (void* addr, const std::string& name)
        {
            os << '\t' << addr << ' ' << name << '\n';
        });
        return os;
    }

    class ErrorDetailsThrowsInDestructor
    {
    public:
        ErrorDetailsThrowsInDestructor()
        {
            aesni_success(get());
        }

        #if defined(_MSC_VER) && _MSC_VER < 1900
        ~ErrorDetailsThrowsInDestructor()
        #else
        ~ErrorDetailsThrowsInDestructor() noexcept(false)
        #endif
        {
            if (aesni_is_error(aesni_get_error_code(get())))
                throw Error(m_impl);
        }

        AesNI_ErrorDetails* get() { return &m_impl; }

        operator AesNI_ErrorDetails*() { return get(); }

    private:
        AesNI_ErrorDetails m_impl;
    };
}

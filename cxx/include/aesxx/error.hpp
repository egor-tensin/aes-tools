// Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
// This file is part of the "AES tools" project.
// For details, see https://github.com/egor-tensin/aes-tools.
// Distributed under the MIT License.

#pragma once

#include "debug.hpp"

#include <aes/all.h>

#include <boost/config.hpp>

#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <functional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace aes
{
    class Error : public std::runtime_error
    {
    public:
        Error(const AES_ErrorDetails& err_details)
            : std::runtime_error{format_error_message(err_details)}
        {
            fill_call_stack(err_details);
        }

        void for_each_addr(
            const std::function<void (const void*, const std::string&)>& callback) const
        {
            aux::CallStackFormatter formatter;

            std::for_each(
                call_stack,
                call_stack + call_stack_len,
                [&formatter, &callback] (const void* addr)
            {
                callback(addr, formatter.format_address(addr));
            });
        }

    private:
        static std::string format_error_message(const AES_ErrorDetails& err_details)
        {
            std::vector<char> buf;
            buf.resize(aes_format_error(&err_details, NULL, 0));
            aes_format_error(&err_details, buf.data(), buf.size());
            return {buf.begin(), buf.end()};
        }

        void fill_call_stack(const AES_ErrorDetails& err_details)
        {
            call_stack_len = err_details.call_stack_len;

            if (call_stack_len > AES_MAX_CALL_STACK_LENGTH)
                call_stack_len = AES_MAX_CALL_STACK_LENGTH;

            std::memcpy(call_stack, err_details.call_stack, call_stack_len * sizeof(const void*));
        }

        std::size_t call_stack_len = 0;
        const void* call_stack[AES_MAX_CALL_STACK_LENGTH] = {nullptr};
    };

    inline std::ostream& operator<<(std::ostream& os, const Error& error)
    {
        os << "AES error: " << error.what() << '\n';
        os << "Call stack:\n";
        error.for_each_addr([&os] (const void* addr, const std::string& name)
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
            aes_success(get());
        }

        ~ErrorDetailsThrowsInDestructor() BOOST_NOEXCEPT_IF(false)
        {
            if (aes_is_error(aes_get_error_code(get())))
                throw Error(impl);
        }

        AES_ErrorDetails* get() { return &impl; }

        operator AES_ErrorDetails*() { return get(); }

    private:
        AES_ErrorDetails impl;
    };
}

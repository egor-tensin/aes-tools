/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#ifdef WIN32
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.Lib")
#endif

#include <cstddef>

#include <sstream>
#include <string>

namespace aes
{
    namespace aux
    {
        class CallStackFormatter
        {
        public:
            CallStackFormatter() = default;

            std::string format_address(const void* addr) const
            {
                #ifdef WIN32
                return format_address_win32(addr);
                #else
                return format_address_fallback(addr);
                #endif
            }

        private:
            template <typename T>
            static std::string put_between_brackets(const T& x)
            {
                std::ostringstream oss;
                oss << "[" << x << "]";
                return oss.str();
            }

            template <typename T>
            static std::string stringify(const T& x)
            {
                std::ostringstream oss;
                oss << x;
                return oss.str();
            }

            static std::string format_address_fallback(const void* addr)
            {
                return put_between_brackets(addr);
            }

            static std::string format_module(
                const std::string& module_name,
                const void* offset = nullptr)
            {
                if (offset == nullptr)
                    return put_between_brackets(module_name);
                else
                    return put_between_brackets(module_name + "+" + stringify(offset));
            }

            static std::string format_symbol(
                const std::string& symbol_name,
                const void* offset = nullptr)
            {
                return format_module(symbol_name, offset);
            }

            static std::string format_symbol(
                const std::string& module_name,
                const std::string& symbol_name,
                const void* offset = nullptr)
            {
                return format_symbol(module_name + "!" + symbol_name, offset);
            }

            #ifdef WIN32
            class DbgHelp
            {
            public:
                DbgHelp()
                {
                    initialized_flag = SymInitialize(GetCurrentProcess(), NULL, TRUE) != FALSE;
                }

                bool initialized() const
                {
                    return initialized_flag;
                }

                ~DbgHelp()
                {
                    if (initialized_flag)
                        SymCleanup(GetCurrentProcess());
                }

            private:
                bool initialized_flag = false;

                DbgHelp(const DbgHelp&) = delete;
                DbgHelp& operator=(const DbgHelp&) = delete;
            };

            DbgHelp dbghelp;

            std::string format_address_win32(const void* addr) const
            {
                if (!dbghelp.initialized())
                    return format_address_fallback(addr);

                DWORD64 symbol_info_buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
                const auto symbol_info = reinterpret_cast<SYMBOL_INFO*>(symbol_info_buf);
                symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
                symbol_info->MaxNameLen = MAX_SYM_NAME;

                IMAGEHLP_MODULE64 module_info;
                module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

                DWORD64 symbol_offset;

                const auto symbol_resolved = SymFromAddr(
                    GetCurrentProcess(),
                    reinterpret_cast<DWORD64>(addr),
                    &symbol_offset,
                    symbol_info);

                if (symbol_resolved)
                {
                    const auto module_resolved = SymGetModuleInfo64(
                        GetCurrentProcess(),
                        symbol_info->ModBase,
                        &module_info);

                    if (module_resolved)
                    {
                        return format_symbol(
                            module_info.ModuleName,
                            symbol_info->Name,
                            reinterpret_cast<const void*>(symbol_offset));
                    }
                    else
                    {
                        return format_symbol(symbol_info->Name, addr);
                    }
                }
                else
                {
                    const auto module_resolved = SymGetModuleInfo64(
                        GetCurrentProcess(),
                        reinterpret_cast<DWORD64>(addr),
                        &module_info);

                    if (module_resolved)
                    {
                        const auto module_offset = reinterpret_cast<const char*>(addr) - module_info.BaseOfImage;
                        return format_module(module_info.ModuleName, module_offset);
                    }
                    else
                    {
                        return format_address_fallback(addr);
                    }
                }
            }
            #endif
        };
    }
}

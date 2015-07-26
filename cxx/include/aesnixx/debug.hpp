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
#pragma warning(push)
#pragma warning(disable: 4091)
#include <DbgHelp.h>
#pragma warning(pop)
#pragma comment(lib, "dbghelp.lib")
#endif

#include <cstddef>

#include <sstream>
#include <string>

namespace aesni
{
    namespace aux
    {
        class CallStackFormatter
        {
        public:
            CallStackFormatter()
            {
                #ifdef WIN32
                valid_flag = SymInitialize(GetCurrentProcess(), NULL, TRUE) ? true : false;
                #endif
            }

            std::string format(void* addr) const
            {
                #ifdef WIN32
                if (!valid_flag)
                    return format_fallback(addr);

                DWORD64 symbol_info_buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
                PSYMBOL_INFO symbol_info = (PSYMBOL_INFO) symbol_info_buf;
                symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
                symbol_info->MaxNameLen = MAX_SYM_NAME;

                IMAGEHLP_MODULE64 module_info;
                module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

                DWORD64 displacement_within_symbol;

                if (!SymFromAddr(GetCurrentProcess(), reinterpret_cast<DWORD64>(addr), &displacement_within_symbol, symbol_info))
                {
                    if (!SymGetModuleInfo64(GetCurrentProcess(), reinterpret_cast<DWORD64>(addr), &module_info))
                        return format_fallback(addr);

                    void* const displacement_within_module = reinterpret_cast<char*>(addr) - module_info.BaseOfImage;
                    return format_with_module(module_info.ModuleName, displacement_within_module);
                }

                if (!SymGetModuleInfo64(GetCurrentProcess(), symbol_info->ModBase, &module_info))
                    return format_with_symbol(symbol_info->Name, addr);

                return format_with_symbol_and_module(symbol_info->Name, module_info.ModuleName, reinterpret_cast<void*>(displacement_within_symbol));
                #else
                return format_fallback(addr);
                #endif
            }

            ~CallStackFormatter()
            {
                #ifdef WIN32
                if (valid_flag)
                    SymCleanup(GetCurrentProcess());
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

            std::string format_fallback(void* addr) const
            {
                return put_between_brackets(addr);
            }

            std::string format_with_module(const std::string& module_name, void* displacement) const
            {
                if (displacement == NULL)
                    return put_between_brackets(module_name);
                else
                    return put_between_brackets(module_name + "+" + stringify(displacement));
            }

            std::string format_with_symbol(const std::string& symbol_name, void* displacement) const
            {
                return format_with_module(symbol_name, displacement);
            }

            std::string format_with_symbol_and_module(const std::string& symbol_name, const std::string& module_name, void* displacement) const
            {
                return format_with_symbol(module_name + "!" + symbol_name, displacement);
            }

            #ifdef WIN32
            bool valid_flag = false;
            #endif
        };
    }
}

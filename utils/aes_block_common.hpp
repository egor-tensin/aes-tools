/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#pragma once

#include <aesnixx/all.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

#include <cstdlib>

#include <deque>
#include <iostream>
#include <iterator>
#include <istream>
#include <string>
#include <vector>

static std::istream& operator>>(std::istream& is, aesni::Mode& dest)
{
    std::string src;
    is >> src;

    if (boost::iequals(src, "ecb"))
        dest = AESNI_ECB;
    else if (boost::iequals(src, "cbc"))
        dest = AESNI_CBC;
    else if (boost::iequals(src, "cfb"))
        dest = AESNI_CFB;
    else if (boost::iequals(src, "ofb"))
        dest = AESNI_OFB;
    else if (boost::iequals(src, "ctr"))
        dest = AESNI_CTR;
    else
        throw boost::program_options::validation_error(boost::program_options::validation_error::invalid_option_value, "mode", src);

    return is;
}

static std::istream& operator>>(std::istream& is, aesni::Algorithm& dest)
{
    std::string src;
    is >> src;

    if (boost::iequals(src, "aes128"))
        dest = AESNI_AES128;
    else if (boost::iequals(src, "aes192"))
        dest = AESNI_AES192;
    else if (boost::iequals(src, "aes256"))
        dest = AESNI_AES256;
    else
        throw boost::program_options::validation_error(boost::program_options::validation_error::invalid_option_value, "algorithm", src);

    return is;
}

namespace
{
    class CommandLineParser
    {
    public:
        CommandLineParser(const std::string& prog_name)
            : prog_name(prog_name)
            , options("Options")
            , boxes_flag(false)
            , verbose_flag(false)
        { }

        bool parse_options(int argc, char** argv)
        {
            namespace po = boost::program_options;

            options.add_options()
                ("help,h", "show this message and exit")
                ("box,b", po::bool_switch(&boxes_flag)->default_value(false), "use the \"boxes\" interface")
                ("mode,m", po::value<aesni::Mode>(&encryption_mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aesni::Algorithm>(&encryption_algo)->required(), "set algorithm")
                ("verbose,v", po::bool_switch(&verbose_flag)->default_value(false), "enable verbose output");

            po::options_description hidden_options;
            hidden_options.add_options()
                ("positional", po::value<std::vector<std::string>>(&args));

            po::options_description all_options;
            all_options.add(options).add(hidden_options);

            po::positional_options_description positional_options;
            positional_options.add("positional", -1);

            po::variables_map vm;
            po::store(po::command_line_parser(argc, argv).options(all_options).positional(positional_options).run(), vm);

            if (vm.count("help"))
            {
                print_usage();
                return false;
            }

            po::notify(vm);
            return true;
        }

        void print_usage()
        {
            std::cout << "Usage: " << prog_name << " [OPTIONS...] [-- KEY [IV] [BLOCK...]...]\n";
            std::cout << options << "\n";
        }

        aesni::Mode get_mode() const
        {
            return encryption_mode;
        }

        aesni::Algorithm get_algorithm() const
        {
            return encryption_algo;
        }

        bool use_boxes() const
        {
            return boxes_flag;
        }

        std::deque<std::string> get_args()
        {
            return { std::make_move_iterator(args.begin()), std::make_move_iterator(args.end()) };
        }

        bool verbose() const
        {
            return verbose_flag;
        }

    private:
        const std::string prog_name;
        boost::program_options::options_description options;

        aesni::Mode encryption_mode;
        aesni::Algorithm encryption_algo;
        bool boxes_flag;
        std::vector<std::string> args;
        bool verbose_flag;
    };
}

namespace
{
    template <aesni::Algorithm algorithm>
    void dump_block(const char* name, const typename aesni::Types<algorithm>::Block& block)
    {
        std::cout << name << ": " << aesni::to_string<algorithm>(block) << "\n" << aesni::to_matrix_string<algorithm>(block) << "\n";
    }

    template <aesni::Algorithm algorithm>
    void dump_plaintext(const typename aesni::Types<algorithm>::Block& block)
    {
        dump_block<algorithm>("Plaintext", block);
    }

    template <aesni::Algorithm algorithm>
    void dump_key(const typename aesni::Types<algorithm>::Key& key)
    {
        std::cout << "Key: " << aesni::to_string<algorithm>(key) << "\n\n";
    }

    template <aesni::Algorithm algorithm>
    void dump_ciphertext(const typename aesni::Types<algorithm>::Block& ciphertext)
    {
        dump_block<algorithm>("Ciphertext", ciphertext);
    }

    template <aesni::Algorithm algorithm>
    void dump_iv(const typename aesni::Types<algorithm>::Block& iv)
    {
        dump_block<algorithm>("Initialization vector", iv);
    }

    template <aesni::Algorithm algorithm>
    void dump_round_keys(const char* name, const typename aesni::Types<algorithm>::RoundKeys& round_keys)
    {
        std::cout << name << ":\n";
        for (std::size_t i = 0; i < aesni::get_number_of_rounds<algorithm>(); ++i)
            std::cout << "\t[" << i << "]: " << aesni::to_string<algorithm>(round_keys.keys[i]) << "\n";
        std::cout << "\n";
    }

    template <aesni::Algorithm algorithm>
    void dump_encryption_keys(const typename aesni::Types<algorithm>::RoundKeys& round_keys)
    {
        dump_round_keys<algorithm>("Encryption round keys", round_keys);
    }

    template <aesni::Algorithm algorithm>
    void dump_decryption_keys(const typename aesni::Types<algorithm>::RoundKeys& round_keys)
    {
        dump_round_keys<algorithm>("Decryption round keys", round_keys);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode>
    void dump_wrapper(
        const aesni::EncryptWrapper<algorithm, mode>& wrapper)
    {
        dump_encryption_keys<algorithm>(wrapper.encryption_keys);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode>
    void dump_wrapper(
        const aesni::DecryptWrapper<algorithm, mode>& wrapper)
    {
        dump_decryption_keys<algorithm>(wrapper.decryption_keys);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode, typename std::enable_if<aesni::ModeRequiresInitializationVector<mode>::value>::type* = 0>
    void dump_next_iv(
        const aesni::EncryptWrapper<algorithm, mode>& wrapper)
    {
        dump_block<algorithm>("Next initialization vector", wrapper.iv);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode, typename std::enable_if<!aesni::ModeRequiresInitializationVector<mode>::value>::type* = 0>
    void dump_next_iv(
        const aesni::EncryptWrapper<algorithm, mode>&)
    { }

    template <aesni::Algorithm algorithm, aesni::Mode mode, typename std::enable_if<aesni::ModeRequiresInitializationVector<mode>::value>::type* = 0>
    void dump_next_iv(
        const aesni::DecryptWrapper<algorithm, mode>& wrapper)
    {
        dump_block<algorithm>("Next initialization vector", wrapper.iv);
    }

    template <aesni::Algorithm algorithm, aesni::Mode mode, typename std::enable_if<!aesni::ModeRequiresInitializationVector<mode>::value>::type* = 0>
    void dump_next_iv(
        const aesni::DecryptWrapper<algorithm, mode>&)
    { }
}

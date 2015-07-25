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
        CommandLineParser(const std::string& program_name)
            : m_program_name(program_name)
            , m_options("Options")
            , m_boxes(false)
            , m_verbose(false)
        { }

        bool parse_options(int argc, char** argv)
        {
            namespace po = boost::program_options;

            m_options.add_options()
                ("help,h", "show this message and exit")
                ("box,b", po::bool_switch(&m_boxes)->default_value(false), "use the \"boxes\" interface")
                ("mode,m", po::value<aesni::Mode>(&m_mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aesni::Algorithm>(&m_algorithm)->required(), "set algorithm")
                ("verbose,v", po::bool_switch(&m_verbose)->default_value(false), "enable verbose output");

            po::options_description hidden_options;
            hidden_options.add_options()
                ("positional", po::value<std::vector<std::string>>(&m_args));

            po::options_description all_options;
            all_options.add(m_options).add(hidden_options);

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
            std::cout << "Usage: " << m_program_name << " [OPTIONS...] [-- KEY [IV] [BLOCK...]...]\n";
            std::cout << m_options << "\n";
        }

        aesni::Mode get_mode() const
        {
            return m_mode;
        }

        aesni::Algorithm get_algorithm() const
        {
            return m_algorithm;
        }

        bool use_boxes() const
        {
            return m_boxes;
        }

        std::deque<std::string> get_args()
        {
            return { std::make_move_iterator(m_args.begin()), std::make_move_iterator(m_args.end()) };
        }

        bool verbose() const
        {
            return m_verbose;
        }

    private:
        const std::string m_program_name;
        boost::program_options::options_description m_options;

        aesni::Mode m_mode;
        aesni::Algorithm m_algorithm;
        bool m_boxes;
        std::vector<std::string> m_args;
        bool m_verbose;
    };
}

namespace
{
    void dump_block(const char* name, const aesni::aes::Block& block)
    {
        std::cout << name << ": " << aesni::aes::to_string(block) << "\n" << aesni::aes::to_matrix_string(block) << "\n";
    }

    void dump_plaintext(const aesni::aes::Block& block)
    {
        dump_block("Plaintext", block);
    }

    template <typename KeyT>
    void dump_key(const KeyT& key)
    {
        std::cout << "Key: " << aesni::aes::to_string(key) << "\n\n";
    }

    void dump_ciphertext(const aesni::aes::Block& ciphertext)
    {
        dump_block("Ciphertext", ciphertext);
    }

    void dump_iv(const aesni::aes::Block& iv)
    {
        dump_block("Initialization vector", iv);
    }

    void dump_next_iv(const aesni::aes::Block& next_iv)
    {
        dump_block("Next initialization vector", next_iv);
    }

    template <typename RoundKeysT>
    void dump_round_keys(const char* name, const RoundKeysT& round_keys)
    {
        std::cout << name << ":\n";
        for (std::size_t i = 0; i < aesni::aes::get_number_of_rounds(round_keys); ++i)
            std::cout << "\t[" << i << "]: " << aesni::aes::to_string(round_keys.keys[i]) << "\n";
        std::cout << "\n";
    }

    template <typename RoundKeysT>
    void dump_encryption_keys(const RoundKeysT& round_keys)
    {
        dump_round_keys("Encryption round keys", round_keys);
    }

    template <typename RoundKeysT>
    void dump_decryption_keys(const RoundKeysT& round_keys)
    {
        dump_round_keys("Decryption round keys", round_keys);
    }

    template <aesni::Algorithm algo, aesni::Mode mode>
    struct Dumper;

    template <aesni::Algorithm algo>
    struct Dumper<algo, AESNI_ECB>
    {
        static void dump_round_keys(const aesni::aes::Encrypt<algo, AESNI_ECB>& encrypt)
        {
            dump_encryption_keys(encrypt.encryption_keys);
            dump_decryption_keys(encrypt.decryption_keys);
        }

        static void dump_next_iv(const aesni::aes::Encrypt<algo, AESNI_ECB>&)
        { }
    };

    template <aesni::Algorithm algo>
    struct Dumper<algo, AESNI_CBC>
    {
        static void dump_round_keys(const aesni::aes::Encrypt<algo, AESNI_CBC>& encrypt)
        {
            dump_encryption_keys(encrypt.encryption_keys);
            dump_decryption_keys(encrypt.decryption_keys);
        }

        static void dump_next_iv(const aesni::aes::Encrypt<algo, AESNI_CBC>&)
        { }
    };

    template <aesni::Algorithm algo>
    struct Dumper<algo, AESNI_CFB>
    {
        static void dump_round_keys(const aesni::aes::Encrypt<algo, AESNI_CFB>& encrypt)
        {
            dump_encryption_keys(encrypt.encryption_keys);
        }

        static void dump_next_iv(const aesni::aes::Encrypt<algo, AESNI_CFB>& encrypt)
        {
            ::dump_next_iv(encrypt.iv);
        }
    };

    template <aesni::Algorithm algo>
    struct Dumper<algo, AESNI_OFB>
    {
        static void dump_round_keys(const aesni::aes::Encrypt<algo, AESNI_OFB>& encrypt)
        {
            dump_encryption_keys(encrypt.encryption_keys);
        }

        static void dump_next_iv(const aesni::aes::Encrypt<algo, AESNI_OFB>& encrypt)
        {
            ::dump_next_iv(encrypt.iv);
        }
    };

    template <aesni::Algorithm algo>
    struct Dumper<algo, AESNI_CTR>
    {
        static void dump_round_keys(const aesni::aes::Encrypt<algo, AESNI_CTR>& encrypt)
        {
            dump_encryption_keys(encrypt.encryption_keys);
        }

        static void dump_next_iv(const aesni::aes::Encrypt<algo, AESNI_CTR>& encrypt)
        {
            ::dump_next_iv(encrypt.iv);
        }
    };
}

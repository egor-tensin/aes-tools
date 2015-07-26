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
        { }

        bool parse_options(int argc, char** argv)
        {
            namespace po = boost::program_options;

            options.add_options()
                ("help,h", "show this message and exit")
                ("mode,m", po::value<aesni::Mode>(&encryption_mode)->required(), "set mode of operation")
                ("algorithm,a", po::value<aesni::Algorithm>(&encryption_algo)->required(), "set algorithm");

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
            std::cout << "Usage: " << prog_name << " [OPTIONS...] KEY [IV] SRC_PATH DEST_PATH\n";
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

        std::deque<std::string> get_args()
        {
            return { std::make_move_iterator(args.begin()), std::make_move_iterator(args.end()) };
        }

    private:
        const std::string prog_name;
        boost::program_options::options_description options;

        aesni::Mode encryption_mode;
        aesni::Algorithm encryption_algo;
        std::vector<std::string> args;
    };
}

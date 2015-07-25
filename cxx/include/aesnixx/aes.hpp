/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include "algorithm.hpp"
#include "data.hpp"
#include "mode.hpp"

#include <aesni/all.h>

#include <string>

#pragma once

namespace aesni
{
    namespace aes
    {
        typedef AesNI_Aes_Block Block;

        typedef AesNI_Aes128_Key Key128;
        typedef AesNI_Aes192_Key Key192;
        typedef AesNI_Aes256_Key Key256;

        inline void make_block(Block& dest, int hi3, int hi2, int lo1, int lo0)
        {
            aesni_aes_make_block(&dest, hi3, hi2, lo1, lo0);
        }

        inline void make_key(Key128& dest, int hi3, int hi2, int lo1, int lo0)
        {
            aesni_aes128_make_key(&dest, hi3, hi2, lo1, lo0);
        }

        inline void make_key(Key192& dest, int hi5, int hi4, int hi3, int lo2, int lo1, int lo0)
        {
            aesni_aes192_make_key(&dest, hi5, hi4, hi3, lo2, lo1, lo0);
        }

        inline void make_key(Key256& dest, int hi7, int hi6, int hi5, int hi4, int lo3, int lo2, int lo1, int lo0)
        {
            aesni_aes256_make_key(&dest, hi7, hi6, hi5, hi4, lo3, lo2, lo1, lo0);
        }

        std::string to_string(const Block& block)
        {
            AesNI_Aes_BlockString str;
            aesni_aes_format_block(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        std::string to_matrix_string(const Block& block)
        {
            AesNI_Aes_BlockMatrixString str;
            aesni_aes_format_block_as_matrix(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        inline void from_string(Block& dest, const char* src)
        {
            aesni_aes_parse_block(&dest, src, ErrorDetailsThrowsInDestructor());
        }

        inline void from_string(Block& dest, const std::string& src)
        {
            from_string(dest, src.c_str());
        }

        std::string to_string(const Key128& block)
        {
            AesNI_Aes128_KeyString str;
            aesni_aes128_format_key(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        std::string to_string(const Key192& block)
        {
            AesNI_Aes192_KeyString str;
            aesni_aes192_format_key(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        std::string to_string(const Key256& block)
        {
            AesNI_Aes256_KeyString str;
            aesni_aes256_format_key(&str, &block, ErrorDetailsThrowsInDestructor());
            return std::string(str.str);
        }

        inline void from_string(Key128& dest, const char* src)
        {
            aesni_aes128_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
        }

        inline void from_string(Key192& dest, const char* src)
        {
            aesni_aes192_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
        }

        inline void from_string(Key256& dest, const char* src)
        {
            aesni_aes256_parse_key(&dest, src, ErrorDetailsThrowsInDestructor());
        }

        inline void from_string(Key128& dest, const std::string& src)
        {
            return from_string(dest, src.c_str());
        }

        inline void from_string(Key192& dest, const std::string& src)
        {
            return from_string(dest, src.c_str());
        }

        inline void from_string(Key256& dest, const std::string& src)
        {
            return from_string(dest, src.c_str());
        }

        typedef AesNI_Aes128_RoundKeys RoundKeys128;
        typedef AesNI_Aes192_RoundKeys RoundKeys192;
        typedef AesNI_Aes256_RoundKeys RoundKeys256;

        template <typename RoundKeysT>
        inline std::size_t get_number_of_rounds(const RoundKeysT& round_keys)
        {
            return sizeof(round_keys) / sizeof(Block128);
        }

        inline void expand_key(
            const Key128& key,
            RoundKeys128& encryption_keys)
        {
            aesni_aes128_expand_key(&key, &encryption_keys);
        }

        inline void expand_key(
            const Key192& key,
            RoundKeys192& encryption_keys)
        {
            aesni_aes192_expand_key(&key, &encryption_keys);
        }

        inline void expand_key(
            const Key256& key,
            RoundKeys256& encryption_keys)
        {
            aesni_aes256_expand_key(&key, &encryption_keys);
        }

        inline void derive_decryption_keys(
            const RoundKeys128& encryption_keys,
            RoundKeys128& decryption_keys)
        {
            aesni_aes128_derive_decryption_keys(
                &encryption_keys, &decryption_keys);
        }

        inline void derive_decryption_keys(
            const RoundKeys192& encryption_keys,
            RoundKeys192& decryption_keys)
        {
            aesni_aes192_derive_decryption_keys(
                &encryption_keys, &decryption_keys);
        }

        inline void derive_decryption_keys(
            const RoundKeys256& encryption_keys,
            RoundKeys256& decryption_keys)
        {
            aesni_aes256_derive_decryption_keys(
                &encryption_keys, &decryption_keys);
        }

        inline Block encrypt_ecb(
            const Block& plaintext,
            const RoundKeys128& encryption_keys)
        {
            return aesni_aes128_encrypt_block_ecb(plaintext, &encryption_keys);
        }

        inline Block decrypt_ecb(
            const Block& ciphertext,
            const RoundKeys128& decryption_keys)
        {
            return aesni_aes128_decrypt_block_ecb(ciphertext, &decryption_keys);
        }

        inline Block encrypt_cbc(
            const Block& plaintext,
            const RoundKeys128& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes128_encrypt_block_cbc(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_cbc(
            const Block& ciphertext,
            const RoundKeys128& decryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes128_decrypt_block_cbc(ciphertext, &decryption_keys, iv, &next_iv);
        }

        inline Block encrypt_cfb(
            const Block& plaintext,
            const RoundKeys128& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes128_encrypt_block_cfb(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_cfb(
            const Block& ciphertext,
            const RoundKeys128& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes128_decrypt_block_cfb(ciphertext, &encryption_keys, iv, &next_iv);
        }

        inline Block encrypt_ofb(
            const Block& plaintext,
            const RoundKeys128& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes128_encrypt_block_ofb(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_ofb(
            const Block& ciphertext,
            const RoundKeys128& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes128_decrypt_block_ofb(ciphertext, &encryption_keys, iv, &next_iv);
        }

        inline Block encrypt_ctr(
            const Block& plaintext,
            const RoundKeys128& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes128_encrypt_block_ctr(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_ctr(
            const Block& ciphertext,
            const RoundKeys128& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes128_decrypt_block_ctr(ciphertext, &encryption_keys, iv, &next_iv);
        }

        inline Block encrypt_ecb(
            const Block& plaintext,
            const RoundKeys192& encryption_keys)
        {
            return aesni_aes192_encrypt_block_ecb(plaintext, &encryption_keys);
        }

        inline Block decrypt_ecb(
            const Block& ciphertext,
            const RoundKeys192& decryption_keys)
        {
            return aesni_aes192_decrypt_block_ecb(ciphertext, &decryption_keys);
        }

        inline Block encrypt_cbc(
            const Block& plaintext,
            const RoundKeys192& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes192_encrypt_block_cbc(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_cbc(
            const Block& ciphertext,
            const RoundKeys192& decryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes192_decrypt_block_cbc(ciphertext, &decryption_keys, iv, &next_iv);
        }

        inline Block encrypt_cfb(
            const Block& plaintext,
            const RoundKeys192& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes192_encrypt_block_cfb(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_cfb(
            const Block& ciphertext,
            const RoundKeys192& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes192_decrypt_block_cfb(ciphertext, &encryption_keys, iv, &next_iv);
        }

        inline Block encrypt_ofb(
            const Block& plaintext,
            const RoundKeys192& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes192_encrypt_block_ofb(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_ofb(
            const Block& ciphertext,
            const RoundKeys192& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes192_decrypt_block_ofb(ciphertext, &encryption_keys, iv, &next_iv);
        }

        inline Block encrypt_ctr(
            const Block& plaintext,
            const RoundKeys192& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes192_encrypt_block_ctr(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_ctr(
            const Block& ciphertext,
            const RoundKeys192& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes192_decrypt_block_ctr(ciphertext, &encryption_keys, iv, &next_iv);
        }

        inline Block encrypt_ecb(
            const Block& plaintext,
            const RoundKeys256& encryption_keys)
        {
            return aesni_aes256_encrypt_block_ecb(plaintext, &encryption_keys);
        }

        inline Block decrypt_ecb(
            const Block& ciphertext,
            const RoundKeys256& decryption_keys)
        {
            return aesni_aes256_decrypt_block_ecb(ciphertext, &decryption_keys);
        }

        inline Block encrypt_cbc(
            const Block& plaintext,
            const RoundKeys256& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes256_encrypt_block_cbc(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_cbc(
            const Block& ciphertext,
            const RoundKeys256& decryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes256_decrypt_block_cbc(ciphertext, &decryption_keys, iv, &next_iv);
        }

        inline Block encrypt_cfb(
            const Block& plaintext,
            const RoundKeys256& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes256_encrypt_block_cfb(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_cfb(
            const Block& ciphertext,
            const RoundKeys256& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes256_decrypt_block_cfb(ciphertext, &encryption_keys, iv, &next_iv);
        }

        inline Block encrypt_ofb(
            const Block& plaintext,
            const RoundKeys256& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes256_encrypt_block_ofb(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_ofb(
            const Block& ciphertext,
            const RoundKeys256& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes256_decrypt_block_ofb(ciphertext, &encryption_keys, iv, &next_iv);
        }

        inline Block encrypt_ctr(
            const Block& plaintext,
            const RoundKeys256& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes256_encrypt_block_ctr(plaintext, &encryption_keys, iv, &next_iv);
        }

        inline Block decrypt_ctr(
            const Block& ciphertext,
            const RoundKeys256& encryption_keys,
            const Block& iv,
            Block& next_iv)
        {
            return aesni_aes256_decrypt_block_ctr(ciphertext, &encryption_keys, iv, &next_iv);
        }

        template <Algorithm>
        struct Types;

        template <>
        struct Types<AESNI_AES128>
        {
            typedef aesni::aes::Block BlockT;
            typedef aesni::aes::Key128 KeyT;
            typedef aesni::aes::RoundKeys128 RoundKeysT;
        };

        template <>
        struct Types<AESNI_AES192>
        {
            typedef aesni::aes::Block BlockT;
            typedef aesni::aes::Key192 KeyT;
            typedef aesni::aes::RoundKeys192 RoundKeysT;
        };

        template <>
        struct Types<AESNI_AES256>
        {
            typedef aesni::aes::Block BlockT;
            typedef aesni::aes::Key256 KeyT;
            typedef aesni::aes::RoundKeys256 RoundKeysT;
        };

        template <Algorithm algorithm, Mode mode>
        struct Encrypt;

        template <Algorithm algorithm>
        struct Encrypt<algorithm, AESNI_ECB>
        {
            Encrypt(const typename Types<algorithm>::KeyT& key,
                    const typename Types<algorithm>::BlockT& iv)
            {
                expand_key(key, encryption_keys);
                derive_decryption_keys(encryption_keys, decryption_keys);
            }

            inline typename Types<algorithm>::BlockT encrypt(const typename Types<algorithm>::BlockT& plaintext)
            {
                return encrypt_ecb(plaintext, encryption_keys);
            }

            inline typename Types<algorithm>::BlockT decrypt(const typename Types<algorithm>::BlockT& ciphertext)
            {
                return decrypt_ecb(ciphertext, decryption_keys);
            }

            typename Types<algorithm>::RoundKeysT encryption_keys;
            typename Types<algorithm>::RoundKeysT decryption_keys;
        };

        template <Algorithm algorithm>
        struct Encrypt<algorithm, AESNI_CBC>
        {
            Encrypt(const typename Types<algorithm>::KeyT& key,
                    const typename Types<algorithm>::BlockT& iv)
                : iv(iv)
            {
                expand_key(key, encryption_keys);
                derive_decryption_keys(encryption_keys, decryption_keys);
            }

            inline typename Types<algorithm>::BlockT encrypt(const typename Types<algorithm>::BlockT& plaintext)
            {
                return encrypt_cbc(plaintext, encryption_keys, iv, iv);
            }

            inline typename Types<algorithm>::BlockT decrypt(const typename Types<algorithm>::BlockT& ciphertext)
            {
                return decrypt_cbc(ciphertext, decryption_keys, iv, iv);
            }

            typename Types<algorithm>::BlockT iv;
            typename Types<algorithm>::RoundKeysT encryption_keys;
            typename Types<algorithm>::RoundKeysT decryption_keys;
        };

        template <Algorithm algorithm>
        struct Encrypt<algorithm, AESNI_CFB>
        {
            Encrypt(const typename Types<algorithm>::KeyT& key,
                    const typename Types<algorithm>::BlockT& iv)
                : iv(iv)
            {
                expand_key(key, encryption_keys);
            }

            inline typename Types<algorithm>::BlockT encrypt(const typename Types<algorithm>::BlockT& plaintext)
            {
                return encrypt_cfb(plaintext, encryption_keys, iv, iv);
            }

            inline typename Types<algorithm>::BlockT decrypt(const typename Types<algorithm>::BlockT& ciphertext)
            {
                return decrypt_cfb(ciphertext, encryption_keys, iv, iv);
            }

            typename Types<algorithm>::BlockT iv;
            typename Types<algorithm>::RoundKeysT encryption_keys;
        };

        template <Algorithm algorithm>
        struct Encrypt<algorithm, AESNI_OFB>
        {
            Encrypt(const typename Types<algorithm>::KeyT& key,
                    const typename Types<algorithm>::BlockT& iv)
                : iv(iv)
            {
                expand_key(key, encryption_keys);
            }

            inline typename Types<algorithm>::BlockT encrypt(const typename Types<algorithm>::BlockT& plaintext)
            {
                return encrypt_ofb(plaintext, encryption_keys, iv, iv);
            }

            inline typename Types<algorithm>::BlockT decrypt(const typename Types<algorithm>::BlockT& ciphertext)
            {
                return decrypt_ofb(ciphertext, encryption_keys, iv, iv);
            }

            typename Types<algorithm>::BlockT iv;
            typename Types<algorithm>::RoundKeysT encryption_keys;
        };

        template <Algorithm algorithm>
        struct Encrypt<algorithm, AESNI_CTR>
        {
            Encrypt(const typename Types<algorithm>::KeyT& key,
                    const typename Types<algorithm>::BlockT& iv)
                : iv(iv)
            {
                expand_key(key, encryption_keys);
            }

            inline typename Types<algorithm>::BlockT encrypt(const typename Types<algorithm>::BlockT& plaintext)
            {
                return encrypt_ctr(plaintext, encryption_keys, iv, iv);
            }

            inline typename Types<algorithm>::BlockT decrypt(const typename Types<algorithm>::BlockT& ciphertext)
            {
                return decrypt_ctr(ciphertext, encryption_keys, iv, iv);
            }

            typename Types<algorithm>::RoundKeysT encryption_keys;
            typename Types<algorithm>::BlockT iv;
        };
    }
}

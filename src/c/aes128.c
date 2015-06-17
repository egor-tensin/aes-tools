/**
 * \file
 * \author Egor Tensin <Egor.Tensin@gmail.com>
 * \date 2015
 * \copyright This file is licensed under the terms of the MIT License.
 *            See LICENSE.txt for details.
 */

#include <aesni/all.h>

#include <emmintrin.h>
#include <wmmintrin.h>

AesNI_Aes_Block __fastcall aesni_aes128_encrypt_block_(
    AesNI_Aes_Block plaintext,
    const AesNI_Aes128_RoundKeys* encryption_keys)
{
    plaintext = _mm_xor_si128(plaintext, encryption_keys->keys[0]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[1]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[2]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[3]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[4]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[5]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[6]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[7]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[8]);
    plaintext = _mm_aesenc_si128(plaintext, encryption_keys->keys[9]);
    return _mm_aesenclast_si128(plaintext, encryption_keys->keys[10]);
}

AesNI_Aes_Block __fastcall aesni_aes128_decrypt_block_(
    AesNI_Aes_Block ciphertext,
    const AesNI_Aes128_RoundKeys* decryption_keys)
{
    ciphertext = _mm_xor_si128(ciphertext, decryption_keys->keys[0]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[1]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[2]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[3]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[4]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[5]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[6]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[7]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[8]);
    ciphertext = _mm_aesdec_si128(ciphertext, decryption_keys->keys[9]);
    return _mm_aesdeclast_si128(ciphertext, decryption_keys->keys[10]);
}

static AesNI_Aes_Block __fastcall aesni_aes128_expand_key_assist(
    AesNI_Aes_Block prev,
    AesNI_Aes_Block hwgen)
{
    AesNI_Aes_Block tmp = prev;

    tmp = _mm_slli_si128(tmp, 4);
    prev = _mm_xor_si128(prev, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    prev = _mm_xor_si128(prev, tmp);
    tmp = _mm_slli_si128(tmp, 4);
    prev = _mm_xor_si128(prev, tmp);

    hwgen = _mm_shuffle_epi32(hwgen, 0xff);
    prev = _mm_xor_si128(prev, hwgen);

    return prev;
}

void __fastcall aesni_aes128_expand_key_(
    AesNI_Aes_Block key,
    AesNI_Aes128_RoundKeys* encryption_keys)
{
    AesNI_Block128 prev = encryption_keys->keys[0] = key;
    prev = encryption_keys->keys[1] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x01));
    prev = encryption_keys->keys[2] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x02));
    prev = encryption_keys->keys[3] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x04));
    prev = encryption_keys->keys[4] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x08));
    prev = encryption_keys->keys[5] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x10));
    prev = encryption_keys->keys[6] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x20));
    prev = encryption_keys->keys[7] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x40));
    prev = encryption_keys->keys[8] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x80));
    prev = encryption_keys->keys[9] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x1b));
    prev = encryption_keys->keys[10] = aesni_aes128_expand_key_assist(prev, _mm_aeskeygenassist_si128(prev, 0x36));
}

void __fastcall aesni_aes128_derive_decryption_keys_(
    const AesNI_Aes128_RoundKeys* encryption_keys,
    AesNI_Aes128_RoundKeys* decryption_keys)
{
    decryption_keys->keys[0] = encryption_keys->keys[10];
    decryption_keys->keys[1] = _mm_aesimc_si128(encryption_keys->keys[9]);
    decryption_keys->keys[2] = _mm_aesimc_si128(encryption_keys->keys[8]);
    decryption_keys->keys[3] = _mm_aesimc_si128(encryption_keys->keys[7]);
    decryption_keys->keys[4] = _mm_aesimc_si128(encryption_keys->keys[6]);
    decryption_keys->keys[5] = _mm_aesimc_si128(encryption_keys->keys[5]);
    decryption_keys->keys[6] = _mm_aesimc_si128(encryption_keys->keys[4]);
    decryption_keys->keys[7] = _mm_aesimc_si128(encryption_keys->keys[3]);
    decryption_keys->keys[8] = _mm_aesimc_si128(encryption_keys->keys[2]);
    decryption_keys->keys[9] = _mm_aesimc_si128(encryption_keys->keys[1]);
    decryption_keys->keys[10] = encryption_keys->keys[0];
}

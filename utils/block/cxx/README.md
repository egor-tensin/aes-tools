# Block encryption utilities

Here are a couple of useful block encryption utilities built on top of the library.
Each of the utilities accepts `--help` flag, which can be used to examine utility's usage info.

On older CPUs, you can run the utilities [using Intel SDE](https://github.com/egor-tensin/aesni#running-on-older-cpus).

## aes_encrypt_block.exe

Encrypts 16-byte blocks using AES-128/192/256 in the specified mode of operation.

### Usage examples

For example, to encrypt

* the plaintext block `0x00112233445566778899aabbccddeeff`
* using AES-128 in ECB mode
* with key `0x000102030405060708090a0b0c0d0e0f`,

run:

    aes_encrypt_block.exe -a aes128 -m ecb 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff

To encrypt

* the plaintext block `0x00112233445566778899aabbccddeeff`
* using AES-192 in OFB mode
* with initialization vector `0x22222222222222222222222222222222`
* and key `0x000102030405060708090a0b0c0d0e0f101112131415161718`,

run:

    aes_encrypt_block.exe -a aes192 -m ofb 000102030405060708090a0b0c0d0e0f101112131415161718 22222222222222222222222222222222 00112233445566778899aabbccddeeff

## aes_decrypt_block.exe

Decrypts 16-byte blocks using AES-128/192/256 in the specified mode of operation.

### Usage examples

For example, to decrypt

* the ciphertext block `0x69c4e0d86a7b0430d8cdb78070b4c55a`
* using AES-128 in ECB mode
* with key `0x000102030405060708090a0b0c0d0e0f`,

run:

    aes_decrypt_block.exe -a aes128 -m ecb 000102030405060708090a0b0c0d0e0f 69c4e0d86a7b0430d8cdb78070b4c55a

To decrypt

* the ciphertext block `0x762a5ab50929189cefdb99434790aad8`
* using AES-192 in OFB mode
* with initialization vector `0x22222222222222222222222222222222`
* and key `0x000102030405060708090a0b0c0d0e0f101112131415161718`,

run:

    aes_decrypt_block.exe -a aes192 -m ofb 000102030405060708090a0b0c0d0e0f101112131415161718 22222222222222222222222222222222 bda298884f5c3a9eb7068aa7063a3b75

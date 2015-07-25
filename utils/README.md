# Utilities

Here are a couple of useful utilities built on top of the library.
Each of the utilities accepts the `--help` flag, which can be used to examine
utility's usage info.

The included utilities are:

* [block encryption](#block-encryption) utilities,
* [file encryption](#file-encryption) utilities,
* and [bitmap encryption](#bitmap-encryption) utilities.

On older CPUs, you can run the utilities
[using Intel SDE](../README.md#running-on-older-cpus).

## Block encryption

The block encryption utilities can produce verbose human-readable output,
including round keys, intermediate initialization vector values, etc.
This is primarily intended for debugging purposes.
Enable verbose output by passing the `--verbose` flag to the utilities.
Please note that verbose output can only be produced when *not* using "boxes"
(the `--boxes` flag).

### aes_encrypt_block.exe

Encrypts 16-byte blocks using AES-128/192/256 in the specified mode of
operation.

#### Usage examples

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

### aes_decrypt_block.exe

Decrypts 16-byte blocks using AES-128/192/256 in the specified mode of
operation.

#### Usage examples

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

## File encryption

### aes_encrypt_file.exe

Encrypts a file using AES-128/192/256 in the specified mode of operation.

#### Usage examples

For example, to encrypt the plaintext `input.txt`

* using AES-128 in ECB mode
* with key `0x11111111111111111111111111111111`
* and write the ciphertext to `output.txt`,

run:

    aes_encrypt_file.exe -a aes128 -m ecb 11111111111111111111111111111111 input.txt output.txt

To encrypt the plaintext from `input.txt`

* using AES-192 in OFB mode
* with key `0x111111111111111111111111111111111111111111111111`
* and initialization vector `0x22222222222222222222222222222222`
* and write the ciphertext to `output.txt`:

run

    aes_encrypt_file.exe -a aes192 -m ofb 111111111111111111111111111111111111111111111111 22222222222222222222222222222222 input.txt output.txt

### aes_decrypt_file.exe

Decrypts a file using AES-128/192/256 in the specified mode of operation.

#### Usage examples

To decrypt the ciphertext from `input.txt`

* using AES-128 in ECB mode
* with key `0x11111111111111111111111111111111`
* and write the plaintext to `output.txt`,

run

    aes_decrypt_file.exe -a aes128 -m ecb 11111111111111111111111111111111 input.txt output.txt

To decrypt the ciphertext from `input.txt`

* using AES-192 in OFB mode
* with key `0x111111111111111111111111111111111111111111111111`
* and initialization vector `0x22222222222222222222222222222222`
* and write the plaintext to `output.txt`,

run

    aes_decrypt_file.exe -a aes192 -m ofb 111111111111111111111111111111111111111111111111 22222222222222222222222222222222 input.txt output.txt

## Bitmap encryption

These utilities were developed primarily to demonstrate the drawbacks of using
ECB mode (namely, the fact that identical plaintext blocks get mapped to
identical ciphertext blocks).
This can be explicitly shown using 8-bit-per-pixel bitmaps:

Plaintext BMP | Encrypted in ECB mode | Encrypted in CBC mode
------------- | --------------------- | ---------------------
![Plaintext butterfly](bmp/butterfly.bmp?raw=true) | ![Ciphertext butterfly in ECB mode](bmp/cipherfly_ecb.bmp?raw=true) | ![Ciphertext butterfly in CBC mode](bmp/cipherfly_cbc.bmp?raw=true)

### aes_encrypt_bmp.exe

Encrypts the pixels in a BMP image file, preserving the header.
The usage is the same as for [aes_encrypt_file.exe](#aes_encrypt_fileexe).

### aes_decrypt_bmp.exe

Decrypts the pixels in a BMP image file, preserving the header.
The usage is the same as for [aes_decrypt_file.exe](#aes_decrypt_fileexe).

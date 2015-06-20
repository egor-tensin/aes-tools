# Utilities

Here are a couple of useful utilities built on top of the library.
Each of the utilities accepts `--help` flag, which can be used to examine utility's usage info.

The included utilities are:

* [file encryption](#file-encryption) utilities,
* and [bitmap encryption](#bitmap-encryption) utilities.

On older CPUs, you can run the utilities [using Intel SDE](https://github.com/egor-tensin/aesni#running-on-older-cpus).

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

These utilities were developed primarily to demonstrate the drawbacks of using ECB mode
(namely, the fact that identical plaintext blocks get mapped to identical ciphertext blocks).
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

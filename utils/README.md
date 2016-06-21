Utilities
=========

A couple of useful utilities are built on top of the library.
Each of the utilities accepts the `--help` flag, which can be used to examine
the utility's usage info.

Block encryption
----------------

Block encryption utilities can produce verbose human-readable output, including
round keys, intermediate initialization vector values, etc.
They are primarily intended for debugging purposes.
Enable verbose output by passing the `--verbose` flag.
Please note that verbose output can only be produced when *not* using the
"boxes" interface (the `--use-boxes` flag).

### encrypt_block.exe

Encrypts blocks using the selected algorithm in the specified mode of
operation.

For example, to encrypt

* the plaintext block `0x00112233445566778899aabbccddeeff`
* using AES-128 in ECB mode
* with key `0x000102030405060708090a0b0c0d0e0f`,

run:

    encrypt_block.exe -a aes128 -m ecb 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff

To encrypt

* the plaintext block `0x00112233445566778899aabbccddeeff`
* using AES-192 in OFB mode
* with initialization vector `0x22222222222222222222222222222222`
* and key `0x000102030405060708090a0b0c0d0e0f101112131415161718`,

run:

    encrypt_block.exe -a aes192 -m ofb 000102030405060708090a0b0c0d0e0f101112131415161718 22222222222222222222222222222222 00112233445566778899aabbccddeeff

### decrypt_block.exe

Decrypts blocks using the selected algorithm in the specified mode of
operation.

For example, to decrypt

* the ciphertext block `0x69c4e0d86a7b0430d8cdb78070b4c55a`
* using AES-128 in ECB mode
* with key `0x000102030405060708090a0b0c0d0e0f`,

run:

    decrypt_block.exe -a aes128 -m ecb 000102030405060708090a0b0c0d0e0f 69c4e0d86a7b0430d8cdb78070b4c55a

To decrypt

* the ciphertext block `0x762a5ab50929189cefdb99434790aad8`
* using AES-192 in OFB mode
* with initialization vector `0x22222222222222222222222222222222`
* and key `0x000102030405060708090a0b0c0d0e0f101112131415161718`,

run:

    decrypt_block.exe -a aes192 -m ofb 000102030405060708090a0b0c0d0e0f101112131415161718 22222222222222222222222222222222 bda298884f5c3a9eb7068aa7063a3b75

File encryption
---------------

### encrypt_file.exe

Encrypts a file using the selected algorithm in the specified mode of
operation.

For example, to encrypt the plaintext from `input.txt`

* using AES-128 in ECB mode
* with key `0x11111111111111111111111111111111`
* and write the ciphertext to `output.txt`,

run:

    encrypt_file.exe -a aes128 -m ecb -k 11111111111111111111111111111111 -i input.txt -o output.txt

To encrypt the plaintext from `input.txt`

* using AES-192 in OFB mode
* with key `0x111111111111111111111111111111111111111111111111`
* and initialization vector `0x22222222222222222222222222222222`
* and write the ciphertext to `output.txt`:

run

    encrypt_file.exe -a aes192 -m ofb -k 111111111111111111111111111111111111111111111111 -v 22222222222222222222222222222222 -i input.txt -o output.txt

### decrypt_file.exe

Decrypts a file using the selected algorithm in the specified mode of
operation.

To decrypt the ciphertext from `input.txt`

* using AES-128 in ECB mode
* with key `0x11111111111111111111111111111111`
* and write the plaintext to `output.txt`,

run

    decrypt_file.exe -a aes128 -m ecb -k 11111111111111111111111111111111 -i input.txt -o output.txt

To decrypt the ciphertext from `input.txt`

* using AES-192 in OFB mode
* with key `0x111111111111111111111111111111111111111111111111`
* and initialization vector `0x22222222222222222222222222222222`
* and write the plaintext to `output.txt`,

run

    decrypt_file.exe -a aes192 -m ofb -k 111111111111111111111111111111111111111111111111 -v 22222222222222222222222222222222 -i input.txt -o output.txt

Bitmap encryption
-----------------

These utilities were developed primarily to demonstrate the drawbacks of using
ECB mode (namely, the fact that identical plaintext blocks get mapped to
identical ciphertext blocks).
This can be explicitly shown using 8-bit-per-pixel bitmaps:

Plaintext BMP    | Encrypted in ECB mode | Encrypted in CBC mode
---------------- | --------------------- | ---------------------
![butterfly.bmp] | ![cipherfly_ecb.bmp]  | ![cipherfly_cbc.bmp]

[butterfly.bmp]: bmp/butterfly.bmp
[cipherfly_ecb.bmp]: bmp/cipherfly_ecb.bmp
[cipherfly_cbc.bmp]: bmp/cipherfly_cbc.bmp

### encrypt_bmp.exe

Encrypts the pixels in a BMP image file, preserving the header.
The usage is the same as for [encrypt_file.exe].

[encrypt_file.exe]: #encrypt_fileexe

### decrypt_bmp.exe

Decrypts the pixels in a BMP image file, preserving the header.
The usage is the same as for [decrypt_file.exe].

[decrypt_file.exe]: #decrypt_fileexe

See also
--------

* [Usage on older CPUs]
* [License]

[Usage on older CPUs]: ../README.md#usage-on-older-cpus
[License]: ../README.md#license

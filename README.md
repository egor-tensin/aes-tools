# aesni

Simple AES encryption algorithm implementation using the AES-NI instruction set.

## Building

I've used the compiler and the assembler shipped with Visual Studio Express 2013 with Update 4 for Windows Desktop.

You can generate the solution using CMake and build it using Visual Studio.

## Running on older CPUs

To run programs that are using the AES-NI instruction set on a CPU w/o the support for these instructions, one can use
[Intel Software Development Emulator](https://software.intel.com/en-us/articles/intel-software-development-emulator).
You can then run a program like this:

    > sde -- aes128ecb_encrypt_block.exe 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

## Testing

See [Testing](https://github.com/egor-tensin/aesni/tree/master/test#testing).

## Licensing

This project, including all of the files and their contents, is licensed under the terms of the MIT License.
See LICENSE.txt for details.

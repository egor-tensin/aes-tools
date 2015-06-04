# aesni

Simple AES encryption algorithm implementation using the AES-NI instruction set.

## Building

I've used the compiler and the assembler shipped with Visual Studio Express 2013 with Update 4 for Windows Desktop.

You can generate the solution using CMake and build it using Visual Studio.

To make AES block I/O functions use big-endian by default (also used in the original FIPS standard; required for the tests),
pass the `LIBAESNI_BE_IO_BY_DEFAULT=1` preprocessor definition.
Using CMake, you can pass the definition like this:

    cmake -D CMAKE_C_FLAGS=/DLIBAESNI_BE_IO_BY_DEFAULT=1 ...

## Running on older CPUs

To run programs that are using the AES-NI instruction set on a CPU w/o the support for these instructions, one can use
[Intel Software Development Emulator](https://software.intel.com/en-us/articles/intel-software-development-emulator).
You can then run a program like this:

    sde -- app.exe arg1 arg2...

## Licensing

This project, including all of the files and their contents, is licensed under the terms of the MIT License.
See LICENSE.txt for details.

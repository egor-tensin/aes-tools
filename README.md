# aesni

Simple AES encryption algorithm implementation using the AES-NI instruction
set.

## Building

I've used the compiler and the assembler shipped with Visual Studio Express
2013 with Update 4 for Windows Desktop.

You can generate the solution using CMake and build it using Visual Studio.

Some of the utilities also depend on a few Boost libraries.
In particular, Boost.ProgramOptions has to be built prior to building these
utilities.
To enable CMake to find Boost libraries, pass the path to the root Boost
directory like this:

    cmake -D BOOST_ROOT=C:\workspace\third-party\boost_1_58_0 ...

Remember that in order to link to the static Boost libraries, you also have to
pass `-D Boost_USE_STATIC_LIBS=ON` to CMake.

## Running on older CPUs

To run the executables that are using the AES-NI instruction set on a CPU w/o
the support for these instructions, one can use
[Intel Software Development Emulator](https://software.intel.com/en-us/articles/intel-software-development-emulator).
You can then run an executable like this:

    > sde -- encrypt_block.exe -a aes128 -m ecb -- 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

## Documentation

You can generate the docs using
[Doxygen](http://www.stack.nl/~dimitri/doxygen/).
The docs will be put into the `doc` directory in the repository's root.

## Utilities

See [Utilities](utils#utilities).

## Testing

See [Testing](test#testing).

## Licensing

This project, including all of the files and their contents, is licensed under
the terms of the MIT License.
See [LICENSE.txt](LICENSE.txt) for details.

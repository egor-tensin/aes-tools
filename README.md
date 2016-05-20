# AES tools

Simple AES implementation and utilities.

## Building

To build the project:

1. generate the solution aes_tools.sln using CMake,
2. build the solution using Visual Studio.

Some of the [utilities] also depend on a few Boost libraries.
In particular, Boost.Filesystem, Boost.Program\_options, and Boost.System must
be built prior to building these utilities.
To enable CMake to find Boost libraries, pass the path to the root Boost
directory like this:

    > cmake -D BOOST_ROOT=C:\workspace\third-party\boost_1_58_0 ...

Remember that in order to link to the static Boost libraries, you also have to
pass `-D Boost_USE_STATIC_LIBS=ON` to CMake.

## Usage on older CPUs

To run the executables that are using the AES-NI instruction set on a CPU w/o
the support for these instructions, you can use [Intel Software Development
Emulator].
After you install the emulator, you can run an executable like this:

    > sde -- encrypt_block.exe -a aes128 -m ecb -- 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

## Documentation

You can generate the docs using [Doxygen].
The docs will be put to the `doc/` directory under the project's root.

## Utilities

See [Utilities].

## Testing

See [Testing].

## License

This project, including all of the files and their contents, is licensed under
the terms of the MIT License.
See [LICENSE.txt] for details.



[LICENSE.txt]: LICENSE.txt
[Doxygen]: http://www.stack.nl/~dimitri/doxygen/
[Intel Software Development Emulator]: https://software.intel.com/en-us/articles/intel-software-development-emulator
[testing]: test/README.md
[utilities]: utils/README.md

# Testing

Using the [utilities], you can validate the implementation either by providing
an arbitrary set of inputs (see [Manual testing]) or by using the test vectors
provided by various AES [validation programs].

You can also test that [file encryption] works (at least to some extent).

[utilities]: ../utils/README.md
[Manual testing]: #manual-testing
[Validation programs]: #validation-programs
[File encryption]: #file-encryption

## Manual testing

You can validate the implementation manually using the block
encryption/decryption utilities `encrypt_block.exe` and `decrypt_block.exe`.
Pass the `--help` flag to examine the utility's usage info.

    > encrypt_block.exe -a aes128 -m ecb -- 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

    > decrypt_block.exe -a aes192 -m cbc -- 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b 000102030405060708090a0b0c0d0e0f 4f021db243bc633d7178183a9fa071e8 b4d9ada9ad7dedf4e5e738763f69145a 571b242012fb7ae07fa9baac3df102e0 08b0e27988598881d920a9e64f5615cd
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

## Validation programs

A number of test vectors have been collected from various AES validation
programs/reference implementations.

The test scripts are used in similar fashion:

* they accept the path to the directory with the block encryption/decryption
  utilities,
* they produce log files with short summaries at the end.

In general, each of the scripts counts the number of tests that have failed,
succeeded, ended with an error, and were skipped.
You must therefore make sure that

* no errors occured while running the script,
* all the tests succeeded except for those that were skipped,
* and the skipped tests were skipped for a good reason.

To pass the path of the directory with the required utilities, use the `--path`
parameter.
To allow the utilities to be executed on older CPUs, pass the `--sde`
parameter.
Pass the `--help` parameter to see examine the script's usage info.

### Prerequisites

* Python (3.4 or higher)

### NIST Special Publication 800-38A

To validate the implementation using the inputs from [NIST SP 800-38A], use
`nist-sp-800-32a.py`:

    > nist-sp-800-38a.py -p C:\workspace\personal\build\aes-tools\utils\Debug

[NIST SP 800-38A]: http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

### Cryptographic Algorithm Validation Program

To validate the implementation using the inputs from [CAVP], use `cavp.py`.

    > cavp.py -p C:\workspace\personal\build\aes-tools\utils\Debug

The AES Known Answer Test (KAT) Vectors are used and read from "KAT_AES.zip".

[CAVP]: http://csrc.nist.gov/groups/STM/cavp/

## File encryption

You can also test file encryption using `file.py`.
Its interface and output is similar to the [validation programs] test scripts.
The expected ciphertexts (for encryption) and plaintexts (for decryption),
along with the keys and initialization vectors, are stored in the files under
a separate directory ("file/" by default).

## See also

* [Building the utilities]
* [Usage on older CPUs]
* [License]

[Building the utilities]: ../README.md#building-the-utilities
[Usage on older CPUs]: ../README.md#usage-on-older-cpus
[License]: ../README.md#license

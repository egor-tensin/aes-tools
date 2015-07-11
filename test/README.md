# Testing

After you've [built](../#building) the block encryption/decryption utilities,
you can verify the implementation either [manually](#manually) or
[automatically](#using-test-vectors) using test vectors.

## Manually

You can test the AES implementation using the block encryption/decryption
utilities `aes_encrypt_block.exe` and `aes_decrypt_block.exe`.
Use the `--help` option to examine the usage info of a utility.

For example, for AES-128 in ECB mode:

    > aes_encrypt_block.exe -a aes128 -m ecb -- 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

and for AES-192 in CBC mode:

    > aes_decrypt_block.exe -a aes192 -m cbc -- 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b 000102030405060708090a0b0c0d0e0f 4f021db243bc633d7178183a9fa071e8 b4d9ada9ad7dedf4e5e738763f69145a 571b242012fb7ae07fa9baac3df102e0 08b0e27988598881d920a9e64f5615cd
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

On older CPUs, you can run the utilities
[using Intel SDE](../README.md#running-on-older-cpus).

## Using test vectors

The test scripts are written in Python 3 and have uniform interfaces: they
accept a path to the directory with the block encryption/decryption utilities
and allow to run them [using Intel SDE](../README.md#running-on-older-cpus).
They also write log files with a short summary at the end.
In general, each scripts counts the number of tests that failed, succeeded,
caused an error, and the tests that were skipped.
You must therefore make sure that

* no errors occured while running the tests,
* all the tests succeeded,
* and the skipped tests were skipped for a good reason.

To pass a path to the directory with the required utilities, use the `--path`
parameter.
To make scripts run the utilities using Intel SDE, pass `--sde`.
Use `--help` to see the script's usage details.

### NIST Special Publication 800-38A

To test the implementation against the vectors from
[NIST SP 800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf),
use `nist-sp-800-32a.py`.

    python nist-sp-800-38a.py -p C:\build\utils\Debug

### Cryptographic Algorithm Validation Program

To test the implementation against the vectors from
[CAVP](http://csrc.nist.gov/groups/STM/cavp/), use `cavp.py`.
The AES Known Answer Test (KAT) Vectors are used and read from `KAT_AES.zip`.

    python cavp.py -p C:\build\utils\Debug

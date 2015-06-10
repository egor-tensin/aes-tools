# Testing

After you've [built](https://github.com/egor-tensin/aesni#building) the block encryption/decryption utilities, you can verify the implementation either manually or automatically using test vectors.

## Manually

The block encryption/decryption utilities have uniform interfaces.
For the ECB mode of operation, the usage is:

    aesNNNecb_encrypt_block.exe KEY0 [PLAIN0...] [-- KEY1 [PLAIN1...]...]

and

    aesNNNecb_decrypt_block.exe KEY0 [CIPHER0...] [-- KEY1 [CIPHER1--]...]

where `NNN` is either `128`, `192` or `256`.

For the modes of operation involving initialization vectors (CBC, CFB, OFB, CTR, etc.), use the utilities like this:

    aesNNNxxx_encrypt_block.exe KEY0 IV0 [PLAIN0...] [-- KEY1 IV1 [PLAIN1...]...]

and

    aesNNNxxx_decrypt_block.exe KEY0 IV0 [CIPHER0...] [-- KEY1 IV1 [CIPHER1...]...]

where `NNN` is the same and `xxx` is either `cbc`, `cfb`, `ofb`, `ctr` or some other mode of operation.

For example,

    > aes128ecb_encrypt_block.exe 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

    > aes192cbc_encrypt_block.exe 000102030405060708090a0b0c0d0e0f1011121314151617 1032547698badcfe1032547698badcfe 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff
    92c01276b27eb8baaa3cabe2c661d4a8
    d42bdf90c1a48221a92a5137c1445418
    96248fca82fbefa31345ae7d8fb7933e

On older CPUs, you can run the utilities [using Intel SDE](https://github.com/egor-tensin/aesni#running-on-older-cpus).

## Using test vectors

The test scripts are written in Python 3 and have uniform interfaces: they accept a path to the directory with the block encryption/decryption utilities and allow to run them [using Intel SDE](https://github.com/egor-tensin/aesni#running-on-older-cpus).
They also write log files with a short summary at the end.
In general, each scripts counts the number of tests that failed, succeeded, caused an error, and the tests that were skipped.
You must therefore make sure that

* no errors occured while running the tests,
* all the tests succeeded,
* and the skipped tests were skipped for a good reason.

To pass a path to the directory with the required utilities, use the `--root` parameter.
To make scripts run the utilities using Intel SDE, pass `--sde`.
Use `--help` to see the script's usage details.

### NIST Special Publication 800-38A

To test the implementation against the vectors from [NIST SP 800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) using `800-32a.py`.

    python 800-38a.py -r C:\build\test\Debug

### Cryptographic Algorithm Validation Program

To test the implementation against the vectors from [CAVP](http://csrc.nist.gov/groups/STM/cavp/) using `cavp.py`.
The AES Known Answer Test (KAT) Vectors are used and read from `KAT_AES.zip`.

    python cavp.py -r C:\build\test\Debug

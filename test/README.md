# Testing the implementation

After you've [built](https://github.com/egor-tensin/aesni#building) the basic utilities,
you can verify the implementation either manually or automatically using scripts.

## Manually

The basic utilities have uniform interfaces.
For the ECB mode of operation, the usage is follows:

    aesNNNecb_encrypt.exe KEY [PLAIN...]

and

    aesNNNecb_decrypt.exe KEY [CIPHER...]

For the modes of operation involving initialization vectors (CBC, CFB, OFB, CTR, etc.),
use the utilities like this:

    aesNNNxxx_encrypt.exe KEY INIT_VECTOR [PLAIN...]

and

    aesNNNxxx_decrypt.exe KEY INIT_VECTOR [CIPHER...]

For example,

    > aes128ecb_encrypt.exe 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

    > aes192cbc_encrypt.exe 000102030405060708090a0b0c0d0e0f1011121314151617 1032547698badcfe1032547698badcfe 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff
    92c01276b27eb8baaa3cabe2c661d4a8
    d42bdf90c1a48221a92a5137c1445418
    96248fca82fbefa31345ae7d8fb7933e

On older CPUs, you can run the executables
[using Intel SDE](https://github.com/egor-tensin/aesni#running-on-older-cpus).

## Using test vectors

### From NIST 800-38A

You can test the implementation against the vectors from
[NIST Special Publication 800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf)
using `800-32a.py`.

The script is written in Python 3, so you need to be able to run Python 3 scripts prior to testing.
Then you can run the script, passing the path to the directory with the required `*_encrypt.exe` and `*_decrypt.exe` files like this:

    python 800-32a.py -r C:\build\test\Debug

On older CPUs, you can make the script run the executables
[using Intel SDE](https://github.com/egor-tensin/aesni#running-on-older-cpus)
using

    python 800-32a.py -r C:\build\test\Debug -e

The script writes a log file, with a short summary at the end.

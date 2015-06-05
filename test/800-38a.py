# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

if __name__ == '__main__':
    import argparse, json, toolkit, sys
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', '-r', required=True,
                        help='set path to *.exe files')
    parser.add_argument('--sde', '-e', action='store_true',
                        help='use Intel SDE to run *.exe files')
    args = parser.parse_args()
    tools = toolkit.Tools(args.root, use_sde=args.sde)
    vectors = json.load(open('800-38a.json'))
    success = True
    for prefix in vectors:
        if 'iv' in vectors[prefix]:
            iv = vectors[prefix]['iv']
            encrypt = lambda key, plaintexts: tools.encrypt_with_iv(prefix, key, iv, plaintexts)
            decrypt = lambda key, ciphers: tools.decrypt_with_iv(prefix, key, iv, ciphers)
        else:
            encrypt = lambda key, plaintexts: tools.encrypt(prefix, key, plaintexts)
            decrypt = lambda key, ciphers: tools.decrypt(prefix, key, ciphers)
        key = vectors[prefix]['key']
        plaintexts = vectors[prefix]['plaintexts']
        ciphers = vectors[prefix]['ciphers']
        success = tools.detect_mismatches(plaintexts, encrypt(key, plaintexts), ciphers) and success
        success = tools.detect_mismatches(ciphers, decrypt(key, ciphers), plaintexts) and success
    if success:
        print('No mismatches detected!')
    else:
        print('Detected mismatches!')
        sys.exit(1)

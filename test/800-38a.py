# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

from datetime import datetime
import logging
import toolkit
import unittest

_plaintexts = ['6bc1bee22e409f96e93d7e117393172a',
               'ae2d8a571e03ac9c9eb76fac45af8e51',
               '30c81c46a35ce411e5fbc1191a0a52ef',
               'f69f2445df4f9b17ad2b417be66c3710']

_keys = {toolkit.AES128: '2b7e151628aed2a6abf7158809cf4f3c',
         toolkit.AES192: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
         toolkit.AES256: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'}

_default_iv = '000102030405060708090a0b0c0d0e0f'
_ctr_iv = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

_init_vectors = {toolkit.AES128: {toolkit.CBC: _default_iv,
                                  toolkit.CFB: _default_iv,
                                  toolkit.OFB: _default_iv,
                                  toolkit.CTR: _ctr_iv}}
_init_vectors[toolkit.AES192] = _init_vectors[toolkit.AES128]
_init_vectors[toolkit.AES256] = _init_vectors[toolkit.AES128]

_ciphertexts = {toolkit.AES128: {toolkit.ECB: ['3ad77bb40d7a3660a89ecaf32466ef97',
                                               'f5d3d58503b9699de785895a96fdbaaf',
                                               '43b1cd7f598ece23881b00e3ed030688',
                                               '7b0c785e27e8ad3f8223207104725dd4'],
                                 toolkit.CBC: ['7649abac8119b246cee98e9b12e9197d',
                                               '5086cb9b507219ee95db113a917678b2',
                                               '73bed6b8e3c1743b7116e69e22229516',
                                               '3ff1caa1681fac09120eca307586e1a7'],
                                 toolkit.CFB: ['3b3fd92eb72dad20333449f8e83cfb4a',
                                               'c8a64537a0b3a93fcde3cdad9f1ce58b',
                                               '26751f67a3cbb140b1808cf187a4f4df',
                                               'c04b05357c5d1c0eeac4c66f9ff7f2e6'],
                                 toolkit.OFB: ['3b3fd92eb72dad20333449f8e83cfb4a',
                                               '7789508d16918f03f53c52dac54ed825',
                                               '9740051e9c5fecf64344f7a82260edcc',
                                               '304c6528f659c77866a510d9c1d6ae5e'],
                                 toolkit.CTR: ['874d6191b620e3261bef6864990db6ce',
                                               '9806f66b7970fdff8617187bb9fffdff',
                                               '5ae4df3edbd5d35e5b4f09020db03eab',
                                               '1e031dda2fbe03d1792170a0f3009cee']},
                toolkit.AES192: {toolkit.ECB: ['bd334f1d6e45f25ff712a214571fa5cc',
                                               '974104846d0ad3ad7734ecb3ecee4eef',
                                               'ef7afd2270e2e60adce0ba2face6444e',
                                               '9a4b41ba738d6c72fb16691603c18e0e'],
                                 toolkit.CBC: ['4f021db243bc633d7178183a9fa071e8',
                                               'b4d9ada9ad7dedf4e5e738763f69145a',
                                               '571b242012fb7ae07fa9baac3df102e0',
                                               '08b0e27988598881d920a9e64f5615cd'],
                                 toolkit.CFB: ['cdc80d6fddf18cab34c25909c99a4174',
                                               '67ce7f7f81173621961a2b70171d3d7a',
                                               '2e1e8a1dd59b88b1c8e60fed1efac4c9',
                                               'c05f9f9ca9834fa042ae8fba584b09ff'],
                                 toolkit.OFB: ['cdc80d6fddf18cab34c25909c99a4174',
                                               'fcc28b8d4c63837c09e81700c1100401',
                                               '8d9a9aeac0f6596f559c6d4daf59a5f2',
                                               '6d9f200857ca6c3e9cac524bd9acc92a'],
                                 toolkit.CTR: ['1abc932417521ca24f2b0459fe7e6e0b',
                                               '090339ec0aa6faefd5ccc2c6f4ce8e94',
                                               '1e36b26bd1ebc670d1bd1d665620abf7',
                                               '4f78a7f6d29809585a97daec58c6b050']},
                toolkit.AES256: {toolkit.ECB: ['f3eed1bdb5d2a03c064b5a7e3db181f8',
                                               '591ccb10d410ed26dc5ba74a31362870',
                                               'b6ed21b99ca6f4f9f153e7b1beafed1d',
                                               '23304b7a39f9f3ff067d8d8f9e24ecc7'],
                                 toolkit.CBC: ['f58c4c04d6e5f1ba779eabfb5f7bfbd6',
                                               '9cfc4e967edb808d679f777bc6702c7d',
                                               '39f23369a9d9bacfa530e26304231461',
                                               'b2eb05e2c39be9fcda6c19078c6a9d1b'],
                                 toolkit.CFB: ['dc7e84bfda79164b7ecd8486985d3860',
                                               '39ffed143b28b1c832113c6331e5407b',
                                               'df10132415e54b92a13ed0a8267ae2f9',
                                               '75a385741ab9cef82031623d55b1e471'],
                                 toolkit.OFB: ['dc7e84bfda79164b7ecd8486985d3860',
                                               '4febdc6740d20b3ac88f6ad82a4fb08d',
                                               '71ab47a086e86eedf39d1c5bba97c408',
                                               '0126141d67f37be8538f5a8be740e484'],
                                 toolkit.CTR: ['601ec313775789a5b7a7f504bbf3d228',
                                               'f443e3ca4d62b59aca84e990cacaf5c5',
                                               '2b0930daa23de94ce87017ba2d84988d',
                                               'dfc9c58db67aada613c2dd08457941a6']}}

def _parametrize(cls, tools, algo, mode):
    testloader = unittest.TestLoader()
    testnames = testloader.getTestCaseNames(cls)
    suite = unittest.TestSuite()
    for name in testnames:
        suite.addTest(cls(name, tools, algo, mode))
    return suite

class TestAlgorithm(unittest.TestCase):
    def __init__(self, methodName='runTest', tools=None, algo=None, mode=None):
        super(TestAlgorithm, self).__init__(methodName)
        self._tools = tools
        self._algo = algo
        self._mode = mode

    def test_encrypt(self):
        logging.info('Testing encryption...')
        logging.info('\tAlgorithm: ' + self._algo)
        logging.info('\tMode: ' + self._mode)

        key = _keys[self._algo]
        iv = None
        if self._algo in _init_vectors and self._mode in _init_vectors[self._algo]:
            iv = _init_vectors[self._algo][self._mode]
        ciphertexts = _ciphertexts[self._algo][self._mode]
        input = toolkit.EncryptionInput(key, _plaintexts, iv=iv)
        self.assertEqual(ciphertexts, self._tools.run_encrypt_tool(self._algo, self._mode, input))

    def test_decrypt(self):
        logging.info('Testing decryption...')
        logging.info('\tAlgorithm: ' + self._algo)
        logging.info('\tMode: ' + self._mode)

        key = _keys[self._algo]
        iv = None
        if self._algo in _init_vectors and self._mode in _init_vectors[self._algo]:
            iv = _init_vectors[self._algo][self._mode]
        ciphertexts = _ciphertexts[self._algo][self._mode]
        input = toolkit.DecryptionInput(key, ciphertexts, iv=iv)
        self.assertEqual(_plaintexts, self._tools.run_decrypt_tool(self._algo, self._mode, input))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--root', '-r', required=True,
                        help='set path to *.exe files')
    parser.add_argument('--sde', '-e', action='store_true',
                        help='use Intel SDE to run *.exe files')
    parser.add_argument('--log', '-l', help='set log file path')
    args, _ = parser.parse_known_args()

    tools = toolkit.Tools(args.root, args.sde)

    logging_options = {'format': '%(asctime)s | %(module)s | %(levelname)s | %(message)s',
                       'level': logging.DEBUG}
    if args.log is None:
        logging_options['filename'] = datetime.now().strftime('800-38a_%Y-%m-%d_%H-%M-%S.log')
    else:
        logging_options['filename'] = args.log
    logging.basicConfig(**logging_options)

    suite = unittest.TestSuite()
    for algo in _ciphertexts:
        for mode in _ciphertexts[algo]:
            suite.addTest(_parametrize(TestAlgorithm, tools, algo, mode))
    unittest.TextTestRunner(verbosity=2).run(suite)

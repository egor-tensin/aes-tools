# Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is part of the "AES tools" project.
# For details, see https://github.com/egor-tensin/aes-tools.
# Distributed under the MIT License.

import argparse
from datetime import datetime
from enum import Enum
import logging
import os.path
from subprocess import CalledProcessError
import sys

from toolkit import Algorithm, BlockInput, Mode, Tools

_TEST_PLAINTEXTS = [
    '6bc1bee22e409f96e93d7e117393172a',
    'ae2d8a571e03ac9c9eb76fac45af8e51',
    '30c81c46a35ce411e5fbc1191a0a52ef',
    'f69f2445df4f9b17ad2b417be66c3710'
]

_TEST_KEYS = {
    Algorithm.AES128: '2b7e151628aed2a6abf7158809cf4f3c',
    Algorithm.AES192: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
    Algorithm.AES256: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
}

_TEST_INIT_VECTOR = '000102030405060708090a0b0c0d0e0f'
_TEST_INIT_VECTOR_CTR = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

_TEST_INIT_VECTORS = {
    Algorithm.AES128: {
        Mode.CBC: _TEST_INIT_VECTOR,
        Mode.CFB: _TEST_INIT_VECTOR,
        Mode.OFB: _TEST_INIT_VECTOR,
        Mode.CTR: _TEST_INIT_VECTOR_CTR
    }
}

_TEST_INIT_VECTORS[Algorithm.AES192] = _TEST_INIT_VECTORS[Algorithm.AES128]
_TEST_INIT_VECTORS[Algorithm.AES256] = _TEST_INIT_VECTORS[Algorithm.AES128]

_TEST_CIPHERTEXTS = {
    Algorithm.AES128: {
        Mode.ECB: [
            '3ad77bb40d7a3660a89ecaf32466ef97',
            'f5d3d58503b9699de785895a96fdbaaf',
            '43b1cd7f598ece23881b00e3ed030688',
            '7b0c785e27e8ad3f8223207104725dd4'
        ],
        Mode.CBC: [
            '7649abac8119b246cee98e9b12e9197d',
            '5086cb9b507219ee95db113a917678b2',
            '73bed6b8e3c1743b7116e69e22229516',
            '3ff1caa1681fac09120eca307586e1a7'
        ],
        Mode.CFB: [
            '3b3fd92eb72dad20333449f8e83cfb4a',
            'c8a64537a0b3a93fcde3cdad9f1ce58b',
            '26751f67a3cbb140b1808cf187a4f4df',
            'c04b05357c5d1c0eeac4c66f9ff7f2e6'
        ],
        Mode.OFB: [
            '3b3fd92eb72dad20333449f8e83cfb4a',
            '7789508d16918f03f53c52dac54ed825',
            '9740051e9c5fecf64344f7a82260edcc',
            '304c6528f659c77866a510d9c1d6ae5e'
        ],
        Mode.CTR: [
            '874d6191b620e3261bef6864990db6ce',
            '9806f66b7970fdff8617187bb9fffdff',
            '5ae4df3edbd5d35e5b4f09020db03eab',
            '1e031dda2fbe03d1792170a0f3009cee'
        ]
    },
    Algorithm.AES192: {
        Mode.ECB: [
            'bd334f1d6e45f25ff712a214571fa5cc',
            '974104846d0ad3ad7734ecb3ecee4eef',
            'ef7afd2270e2e60adce0ba2face6444e',
            '9a4b41ba738d6c72fb16691603c18e0e'
        ],
        Mode.CBC: [
            '4f021db243bc633d7178183a9fa071e8',
            'b4d9ada9ad7dedf4e5e738763f69145a',
            '571b242012fb7ae07fa9baac3df102e0',
            '08b0e27988598881d920a9e64f5615cd'
        ],
        Mode.CFB: [
            'cdc80d6fddf18cab34c25909c99a4174',
            '67ce7f7f81173621961a2b70171d3d7a',
            '2e1e8a1dd59b88b1c8e60fed1efac4c9',
            'c05f9f9ca9834fa042ae8fba584b09ff'
        ],
        Mode.OFB: [
            'cdc80d6fddf18cab34c25909c99a4174',
            'fcc28b8d4c63837c09e81700c1100401',
            '8d9a9aeac0f6596f559c6d4daf59a5f2',
            '6d9f200857ca6c3e9cac524bd9acc92a'
        ],
        Mode.CTR: [
            '1abc932417521ca24f2b0459fe7e6e0b',
            '090339ec0aa6faefd5ccc2c6f4ce8e94',
            '1e36b26bd1ebc670d1bd1d665620abf7',
            '4f78a7f6d29809585a97daec58c6b050'
        ]
    },
    Algorithm.AES256: {
        Mode.ECB: [
            'f3eed1bdb5d2a03c064b5a7e3db181f8',
            '591ccb10d410ed26dc5ba74a31362870',
            'b6ed21b99ca6f4f9f153e7b1beafed1d',
            '23304b7a39f9f3ff067d8d8f9e24ecc7'
        ],
        Mode.CBC: [
            'f58c4c04d6e5f1ba779eabfb5f7bfbd6',
            '9cfc4e967edb808d679f777bc6702c7d',
            '39f23369a9d9bacfa530e26304231461',
            'b2eb05e2c39be9fcda6c19078c6a9d1b'
        ],
        Mode.CFB: [
            'dc7e84bfda79164b7ecd8486985d3860',
            '39ffed143b28b1c832113c6331e5407b',
            'df10132415e54b92a13ed0a8267ae2f9',
            '75a385741ab9cef82031623d55b1e471'
        ],
        Mode.OFB: [
            'dc7e84bfda79164b7ecd8486985d3860',
            '4febdc6740d20b3ac88f6ad82a4fb08d',
            '71ab47a086e86eedf39d1c5bba97c408',
            '0126141d67f37be8538f5a8be740e484'
        ],
        Mode.CTR: [
            '601ec313775789a5b7a7f504bbf3d228',
            'f443e3ca4d62b59aca84e990cacaf5c5',
            '2b0930daa23de94ce87017ba2d84988d',
            'dfc9c58db67aada613c2dd08457941a6'
        ]
    }
}

def get_test_plaintexts(*_):
    return _TEST_PLAINTEXTS

def get_test_key(algorithm, *_):
    return _TEST_KEYS[algorithm]

def get_test_iv(algorithm, mode):
    if not mode.requires_init_vector():
        return None
    return _TEST_INIT_VECTORS[algorithm][mode]

def get_test_ciphertexts(algorithm, mode):
    return _TEST_CIPHERTEXTS[algorithm][mode]

def get_tested_algorithms_and_modes():
    for algorithm in _TEST_CIPHERTEXTS:
        for mode in _TEST_CIPHERTEXTS[algorithm]:
            yield algorithm, mode

def verify_test_output(actual, expected):
    if len(actual) != len(expected):
        logging.error('Unexpected output length!')
        logging.error('\tExpected: %d', len(expected))
        logging.error('\tActual: %d', len(actual))
        return False
    if actual != expected:
        logging.error('Expected output:\n' + '\n'.join(expected))
        return False
    return True

class TestExitCode(Enum):
    SUCCESS, FAILURE, ERROR, SKIPPED = range(1, 5)

def run_encryption_test(tools, algorithm, mode, use_boxes=False):
    logging.info('Running encryption test...')
    logging.info('Algorithm: %s', algorithm)
    logging.info('Mode: %s', mode)

    try:
        plaintexts = get_test_plaintexts(algorithm, mode)
        key = get_test_key(algorithm, mode)
        iv = get_test_iv(algorithm, mode)
        expected_ciphertexts = get_test_ciphertexts(algorithm, mode)
        input_ = BlockInput(key, plaintexts, iv=iv)
        actual_ciphertexts = tools.run_encrypt_block(
            algorithm, mode, input_, use_boxes)
        if verify_test_output(actual_ciphertexts, expected_ciphertexts):
            return TestExitCode.SUCCESS
        else:
            return TestExitCode.FAILURE
    except CalledProcessError as e:
        logging.error('Encountered an exception!')
        logging.exception(e)
        return TestExitCode.ERROR

def run_decryption_test(tools, algorithm, mode, use_boxes=False):
    logging.info('Running decryption test...')
    logging.info('Algorithm: %s', algorithm)
    logging.info('Mode: %s', mode)

    try:
        ciphertexts = get_test_ciphertexts(algorithm, mode)
        key = get_test_key(algorithm, mode)
        iv = get_test_iv(algorithm, mode)
        expected_plaintexts = get_test_plaintexts(algorithm, mode)
        input_ = BlockInput(key, ciphertexts, iv=iv)
        actual_plaintexts = tools.run_decrypt_block(
            algorithm, mode, input_, use_boxes)
        if verify_test_output(actual_plaintexts, expected_plaintexts):
            return TestExitCode.SUCCESS
        else:
            return TestExitCode.FAILURE
    except CalledProcessError as e:
        logging.error('Encountered an exception!')
        logging.exception(e)
        return TestExitCode.ERROR

_script_dir = os.path.dirname(__file__)
_script_name = os.path.splitext(os.path.basename(__file__))[0]

def _build_default_log_path():
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    fn = '{}_{}.log'.format(_script_name, timestamp)
    return os.path.join(_script_dir, fn)

def _setup_logging(log_path=None):
    if log_path is None:
        log_path = _build_default_log_path()

    logging.basicConfig(
        filename=log_path,
        format='%(asctime)s | %(module)s | %(levelname)s | %(message)s',
        level=logging.DEBUG)

def run_tests(tools_path=(), use_sde=False, use_boxes=False, log_path=None):
    _setup_logging(log_path)
    tools = Tools(tools_path, use_sde=use_sde)

    exit_codes = []
    for algorithm, mode in get_tested_algorithms_and_modes():
        exit_codes.append(run_encryption_test(
            tools, algorithm, mode, use_boxes=use_boxes))
        exit_codes.append(run_decryption_test(
            tools, algorithm, mode, use_boxes=use_boxes))

    logging.info('Test exit codes:')
    logging.info('\tSkipped:   %d', exit_codes.count(TestExitCode.SKIPPED))
    logging.info('\tError(s):  %d', exit_codes.count(TestExitCode.ERROR))
    logging.info('\tSucceeded: %d', exit_codes.count(TestExitCode.SUCCESS))
    logging.info('\tFailed:    %d', exit_codes.count(TestExitCode.FAILURE))

    if (exit_codes.count(TestExitCode.ERROR) == 0 and
            exit_codes.count(TestExitCode.FAILURE) == 0):
        return 0
    else:
        return 1

def _parse_args(args=None):
    if args is None:
        args = sys.argv[1:]
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', '-p', dest='tools_path', metavar='PATH',
                        nargs='*',
                        help='set block encryption utilities directory path')
    parser.add_argument('--sde', '-e', action='store_true', dest='use_sde',
                        help='use Intel SDE to run the utilities')
    parser.add_argument('--boxes', '-b', action='store_true', dest='use_boxes',
                        help='use the "boxes" interface')
    parser.add_argument('--log', '-l', dest='log_path', metavar='PATH',
                        help='set log file path')
    return parser.parse_args(args)

def main(args=None):
    return run_tests(**vars(_parse_args(args)))

if __name__ == '__main__':
    sys.exit(main())

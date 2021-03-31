# Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is part of the "AES tools" project.
# For details, see https://github.com/egor-tensin/aes-tools.
# Distributed under the MIT License.

import argparse
from contextlib import contextmanager
from enum import Enum
from glob import iglob as glob
import filecmp
import logging
import os
import shutil
from subprocess import CalledProcessError
import sys
from tempfile import NamedTemporaryFile

from toolkit import Algorithm, Mode, Tools


class TestExitCode(Enum):
    SUCCESS, FAILURE, ERROR, SKIPPED = range(1, 5)


_KEY_EXT = 'key'
_IV_EXT = 'iv'
_PLAIN_EXT = 'plain'
_CIPHER_EXT = 'cipher'


def _list_dirs(root_path):
    for path in os.listdir(root_path):
        path = os.path.join(root_path, path)
        if os.path.isdir(path):
            yield path


def _list_files(root_path, ext):
    for path in glob(os.path.join(root_path, '*.{}'.format(ext))):
        if os.path.isfile(path):
            yield path


def _list_keys(root_path):
    return _list_files(root_path, _KEY_EXT)


def _read_first_line(path):
    with open(path) as fd:
        return fd.readline()


def _read_key(key_path):
    return _read_first_line(key_path)


def _read_iv(iv_path):
    return _read_first_line(iv_path)


def _extract_test_name(key_path):
    return os.path.splitext(os.path.basename(key_path))[0]


def _replace_ext(path, new_ext):
    return '{}.{}'.format(os.path.splitext(path)[0], new_ext)


def _extract_iv_path(key_path):
    return _replace_ext(key_path, _IV_EXT)


def _extract_plaintext_path(key_path):
    return _replace_ext(key_path, _PLAIN_EXT)


def _extract_ciphertext_path(key_path):
    return _replace_ext(key_path, _CIPHER_EXT)


@contextmanager
def _make_output_file():
    with NamedTemporaryFile(delete=False) as tmp_file:
        tmp_path = tmp_file.name
        yield tmp_path
    os.remove(tmp_path)


def run_encryption_test(tools, algorithm, mode, key, plaintext_path,
                        ciphertext_path, iv=None, force=False):
    logging.debug('Running encryption test...')
    logging.debug('\tPlaintext file path: %s', plaintext_path)
    logging.debug('\tExpected ciphertext file path: %s', ciphertext_path)
    logging.debug('\tAlgorithm: %s', algorithm)
    logging.debug('\tMode: %s', mode)

    with _make_output_file() as tmp_path:
        logging.debug('\tEncrypted file path: %s', tmp_path)

        try:
            tools.run_encrypt_file(algorithm, mode, key, plaintext_path,
                                   tmp_path, iv)
            if force:
                logging.warning('Overwriting expected ciphertext file')
                shutil.copy(tmp_path, ciphertext_path)
                return TestExitCode.SKIPPED
            if filecmp.cmp(ciphertext_path, tmp_path):
                return TestExitCode.SUCCESS
            logging.error('The encrypted file doesn\'t match the ciphertext file')
            return TestExitCode.FAILURE
        except CalledProcessError as e:
            logging.error('Encountered an exception!')
            logging.exception(e)
            return TestExitCode.ERROR


def run_decryption_test(tools, algorithm, mode, key, plaintext_path,
                        ciphertext_path, iv=None):
    logging.debug('Running decryption test...')
    logging.debug('\tCiphertext file path: %s', ciphertext_path)
    logging.debug('\tExpected plaintext file path: %s', plaintext_path)
    logging.debug('\tAlgorithm: %s', algorithm)
    logging.debug('\tMode: %s', mode)

    with _make_output_file() as tmp_path:
        logging.debug('\tDecrypted file path: %s', tmp_path)

        try:
            tools.run_decrypt_file(algorithm, mode, key, ciphertext_path,
                                   tmp_path, iv)
            if filecmp.cmp(tmp_path, plaintext_path):
                return TestExitCode.SUCCESS
            logging.error('The decrypted file doesn\'t match the plaintext file')
            return TestExitCode.FAILURE
        except CalledProcessError as e:
            logging.error('Encountered an exception!')
            logging.exception(e)
            return TestExitCode.ERROR


def enum_tests(suite_dir):
    suite_dir = os.path.abspath(suite_dir)
    logging.info('Suite directory path: %s', suite_dir)
    for algorithm_dir in _list_dirs(suite_dir):
        algorithm = os.path.basename(algorithm_dir)
        maybe_algorithm = Algorithm.try_parse(algorithm)
        if maybe_algorithm is None:
            logging.warning('Unknown or unsupported algorithm: %s', algorithm)
            continue
        algorithm = maybe_algorithm
        for mode_dir in _list_dirs(algorithm_dir):
            mode = os.path.basename(mode_dir)
            maybe_mode = Mode.try_parse(mode)
            if maybe_mode is None:
                logging.warning('Unknown or unsupported mode: %s', mode)
                continue
            mode = maybe_mode
            for key_path in _list_keys(mode_dir):
                key = _read_key(key_path)
                logging.debug('Key: %s', key)
                test_name = _extract_test_name(key_path)
                logging.debug('Test name: %s', test_name)
                iv = None
                if mode.requires_init_vector():
                    iv_path = _extract_iv_path(key_path)
                    iv = _read_iv(iv_path)
                plaintext_path = _extract_plaintext_path(key_path)
                ciphertext_path = _extract_ciphertext_path(key_path)
                yield algorithm, mode, key, plaintext_path, ciphertext_path, iv


_script_dir = os.path.dirname(__file__)
_script_name = os.path.splitext(os.path.basename(__file__))[0]


def _setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s | %(module)s | %(levelname)s | %(message)s',
        level=level)


def run_tests(suite_path, tools_path=(), verbose=False, use_sde=False, force=False):
    _setup_logging(verbose)
    tools = Tools(tools_path, use_sde=use_sde)
    exit_codes = []

    for test in enum_tests(suite_path):
        exit_codes.append(run_encryption_test(tools, *test, force))
        exit_codes.append(run_decryption_test(tools, *test))

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
                        help='set file encryption utilities directory path')
    parser.add_argument('--sde', '-e', dest='use_sde', action='store_true',
                        help='use Intel SDE to run the utilities')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='verbose log output')
    parser.add_argument('--force', '-f', action='store_true',
                        help='overwrite ciphertext files')
    parser.add_argument('--suite', '-s', dest='suite_path',
                        default=os.path.join(_script_dir, 'data', 'file'),
                        help='set test suite directory path')
    return parser.parse_args(args)


def main(args=None):
    return run_tests(**vars(_parse_args(args)))


if __name__ == '__main__':
    sys.exit(main())

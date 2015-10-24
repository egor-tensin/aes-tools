# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

import toolkit

from datetime import datetime
from glob import iglob as glob
import filecmp
import logging
import os
import shutil
import sys
from tempfile import TemporaryDirectory

class _TestExitCode:
    SUCCESS, FAILURE, ERROR, SKIPPED = range(4)

_KEY_EXT = 'key'
_IV_EXT = 'iv'
_PLAIN_EXT = 'plain'
_CIPHER_EXT = 'cipher'

def _run_encryption_test(tools, tmp_dir, algo, mode, key, plain_path, cipher_path, iv=None, force=False):
    logging.info('Running encryption test...')
    logging.info('\tPlaintext file path: ' + plain_path)
    logging.info('\tExpected ciphertext file path: ' + cipher_path)
    tmp_path = os.path.join(tmp_dir, os.path.basename(cipher_path))
    logging.info('\tEncrypted file path: ' + tmp_path)
    tools.run_encrypt_file(algo, mode, key, plain_path, tmp_path, iv)
    if force:
        logging.info('Overwriting expected ciphertext file')
        shutil.copy(tmp_path, cipher_path)
        return _TestExitCode.SUCCESS
    if filecmp.cmp(cipher_path, tmp_path):
        return _TestExitCode.SUCCESS
    else:
        logging.error('The encrypted file doesn\'t match the ciphertext file')
        return _TestExitCode.FAILURE

def _run_decryption_test(tools, tmp_dir, algo, mode, key, cipher_path, plain_path, iv=None):
    logging.info('Running decryption test...')
    logging.info('\tCiphertext file path: ' + cipher_path)
    logging.info('\tExpected plaintext file path: ' + plain_path)
    tmp_path = os.path.join(tmp_dir, os.path.basename(cipher_path))
    logging.info('\tDecrypted file path: ' + tmp_path)
    tools.run_decrypt_file(algo, mode, key, cipher_path, tmp_path, iv)
    if filecmp.cmp(tmp_path, plain_path):
        return _TestExitCode.SUCCESS
    else:
        logging.error('The decrypted file doesn\'t match the plaintext file')
        return _TestExitCode.FAILURE

def _list_dirs(root_path):
    xs = map(lambda x: os.path.join(root_path, x), os.listdir(root_path))
    return filter(os.path.isdir, xs)

def _list_files(root_path, ext):
    xs = glob(os.path.join(root_path, '*.{}'.format(ext)))
    return filter(os.path.isfile, xs)

def _list_keys(root_path):
    return _list_files(root_path, _KEY_EXT)

def _read_line(path):
    with open(path) as f:
        return f.readline()

def _read_key(key_path):
    return _read_line(key_path)

def _read_iv(iv_path):
    return _read_line(key_path)

def _extract_test_name(key_path):
    return os.path.splitext(os.path.basename(key_path))[0]

def _replace_ext(path, new_ext):
    return '{}.{}'.format(os.path.splitext(path)[0], new_ext)

def _build_iv_path(key_path):
    return _replace_ext(key_path, _IV_EXT)

def _build_plain_path(key_path):
    return _replace_ext(key_path, _PLAIN_EXT)

def _build_cipher_path(key_path):
    return _replace_ext(key_path, _CIPHER_EXT)

def _run_tests(tools, suite_dir, force=False):
    exit_codes = []
    suite_dir = os.path.abspath(suite_dir)
    logging.info('Suite directory path: ' + suite_dir)
    with TemporaryDirectory() as tmp_dir:
        for algo_dir in _list_dirs(suite_dir):
            algo = os.path.basename(algo_dir)
            maybe_algo = toolkit.is_algorithm_supported(algo)
            if maybe_algo is None:
                logging.warn('Unknown or unsupported algorithm: ' + algo)
                exit_codes.append(_TestExitCode.SKIPPED)
                continue
            algo = maybe_algo
            logging.info('Algorithm: ' + algo)
            for mode_dir in _list_dirs(algo_dir):
                mode = os.path.basename(mode_dir)
                maybe_mode = toolkit.is_mode_supported(mode)
                if maybe_mode is None:
                    logging.warn('Unknown or unsupported mode: ' + mode)
                    exit_codes.append(_TestExitCode.SKIPPED)
                    continue
                mode = maybe_mode
                logging.info('Mode: ' + mode)
                for key_path in _list_keys(mode_dir):
                    key = _read_key(key_path)
                    logging.info('Key: ' + key)
                    test_name = _extract_test_name(key_path)
                    logging.info('Test name: ' + test_name)
                    iv = None
                    if toolkit.mode_requires_init_vector(mode):
                        iv_path = _build_iv_path(key_path)
                        iv = _read_iv(iv_path)
                    plain_path = _build_plain_path(key_path)
                    cipher_path = _build_cipher_path(key_path)
                    os.makedirs(os.path.join(tmp_dir, algo, mode))
                    try:
                        exit_codes.append(_run_encryption_test(
                            tools, os.path.join(tmp_dir, algo, mode),
                            algo, mode, key, plain_path, cipher_path, iv, force))
                    except Exception as e:
                        logging.error('Encountered an exception!')
                        logging.exception(e)
                        exit_codes.append(_TestExitCode.ERROR)
                    if not force:
                        try:
                            exit_codes.append(_run_decryption_test(
                                tools, os.path.join(tmp_dir, algo, mode),
                                algo, mode, key, cipher_path, plain_path, iv))
                        except Exception as e:
                            logging.error('Encountered an exception!')
                            logging.exception(e)
                            exit_codes.append(_TestExitCode.ERROR)
    logging.info('Test exit codes:')
    logging.info('\tSkipped:   {0}'.format(exit_codes.count(_TestExitCode.SKIPPED)))
    logging.info('\tError(s):  {0}'.format(exit_codes.count(_TestExitCode.ERROR)))
    logging.info('\tSucceeded: {0}'.format(exit_codes.count(_TestExitCode.SUCCESS)))
    logging.info('\tFailed:    {0}'.format(exit_codes.count(_TestExitCode.FAILURE)))
    if (exit_codes.count(_TestExitCode.ERROR) == 0 and
            exit_codes.count(_TestExitCode.FAILURE) == 0):
        sys.exit()
    else:
        sys.exit(1)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', '-p', nargs='*',
                        help='set path to file encryption utilities')
    parser.add_argument('--sde', '-e', action='store_true',
                        help='use Intel SDE to run *.exe files')
    parser.add_argument('--log', '-l', help='set log file path')
    parser.add_argument('--force', '-f', action='store_true',
                        help='overwrite ciphertext files')
    parser.add_argument('--suite', '-s', default='file',
                        help='set test suite directory path')
    args = parser.parse_args()

    logging_options = {'format': '%(asctime)s | %(module)s | %(levelname)s | %(message)s',
                       'level': logging.DEBUG}
    if args.log is None:
        logging_options['filename'] = datetime.now().strftime('file_%Y-%m-%d_%H-%M-%S.log')
    else:
        logging_options['filename'] = args.log
    logging.basicConfig(**logging_options)

    tools = toolkit.Tools(args.path, use_sde=args.sde, use_boxes=False)
    _run_tests(tools, args.suite, args.force)

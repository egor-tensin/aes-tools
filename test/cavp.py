# Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is part of the "AES tools" project.
# For details, see https://github.com/egor-tensin/aes-tools.
# Distributed under the MIT License.

import argparse
from collections import OrderedDict
from collections.abc import MutableSequence
import configparser
from datetime import datetime
from enum import Enum
import logging
import os.path
from subprocess import CalledProcessError
import sys
from tempfile import TemporaryDirectory
import zipfile

from toolkit import Algorithm, BlockInput, Mode, Tools


class _MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, MutableSequence) and key in self:
            self[key].extend(value)
        else:
            super(OrderedDict, self).__setitem__(key, value)


def verify_test_output(actual, expected):
    if len(actual) != len(expected):
        logging.error('Unexpected output length!')
        logging.error('\tExpected: %d', len(expected))
        logging.error('\tActual: %d', len(actual))
        return False
    if actual != expected:
        logging.error('Expected output:\n%s', '\n'.join(expected))
        return False
    return True


class TestExitCode(Enum):
    SUCCESS, FAILURE, ERROR, SKIPPED = range(1, 5)


class TestFile:
    def __init__(self, path):
        self._path = path
        self._algorithm = None
        self._mode = None
        self._recognized = False
        self._parse_path()
        if not self.recognized():
            return
        self._parse_data()

    def recognized(self):
        return self._recognized

    def algorithm(self):
        return self._algorithm

    def mode(self):
        return self._mode

    def _parse_data_section(self, parser, section):
        keys = parser.get(section, 'key')
        plaintexts = parser.get(section, 'plaintext')
        ciphertexts = parser.get(section, 'ciphertext')
        init_vectors = None
        if self.mode().requires_init_vector():
            init_vectors = parser.get(section, 'iv')
        return keys, plaintexts, ciphertexts, init_vectors

    def _parse_data(self):
        parser = configparser.ConfigParser(
            dict_type=_MultiOrderedDict,
            strict=False,
            interpolation=None,
            empty_lines_in_values=False)
        with open(self._path) as fd:
            parser.read_string(fd.read())
            self._encryption_data = self._parse_data_section(parser, 'ENCRYPT')
            self._decryption_data = self._parse_data_section(parser, 'DECRYPT')

    @staticmethod
    def _gen_inputs(keys, plaintexts, init_vectors):
        if init_vectors is None:
            init_vectors = [None for key in keys]
        for key, plaintext, iv in zip(keys, plaintexts, init_vectors):
            yield BlockInput(key, [plaintext], iv)

    @staticmethod
    def _split_into_chunks(expected_output, inputs, max_len=100):
        for i in range(0, len(inputs), max_len):
            yield expected_output[i:i+max_len], inputs[i:i+max_len]

    def _run_tests(self, tool, inputs, expected_output, use_boxes=False):
        for expected_output_chunk, input_chunk in self._split_into_chunks(expected_output, list(inputs)):
            actual_output = tool(self.algorithm(), self.mode(), input_chunk, use_boxes=use_boxes)
            if not verify_test_output(actual_output, expected_output_chunk):
                return TestExitCode.FAILURE
        return TestExitCode.SUCCESS

    def run_encryption_tests(self, tools, use_boxes=False):
        logging.info('Running encryption tests...')
        if not self.recognized():
            return TestExitCode.SKIPPED
        try:
            keys, plaintexts, ciphertexts, init_vectors = self._encryption_data
            inputs = self._gen_inputs(keys, plaintexts, init_vectors)
            return self._run_tests(tools.run_encrypt_block, inputs, ciphertexts, use_boxes)
        except CalledProcessError as e:
            logging.error('Encountered an exception!')
            logging.exception(e)
            return TestExitCode.ERROR

    def run_decryption_tests(self, tools, use_boxes=False):
        logging.info('Running decryption tests...')
        if not self.recognized():
            return TestExitCode.SKIPPED
        try:
            keys, plaintexts, ciphertexts, init_vectors = self._decryption_data
            inputs = self._gen_inputs(keys, ciphertexts, init_vectors)
            return self._run_tests(tools.run_decrypt_block, inputs, plaintexts, use_boxes)
        except CalledProcessError as e:
            logging.error('Encountered an exception!')
            logging.exception(e)
            return TestExitCode.ERROR

    def _parse_path(self):
        logging.info('Trying to parse test file path \'%s\'...', self._path)
        stub = self._strip_extension(os.path.basename(self._path))
        if not stub: return
        stub = self._strip_algorithm(stub)
        if not stub: return
        stub = self._strip_method(stub)
        if not stub: return
        stub = self._strip_mode(stub)
        if not stub: return
        self._recognized = True

    _RECOGNIZED_EXT = '.rsp'

    def _strip_extension(self, path):
        stub, ext = os.path.splitext(path)
        if ext != self._RECOGNIZED_EXT:
            logging.warning('Unknown test vectors file extension \'%s\'!', self._path)
            return None
        return stub

    def _strip_algorithm(self, stub):
        key_size = stub[-3:]
        maybe_algorithm = 'aes{}'.format(key_size)
        self._algorithm = Algorithm.try_parse(maybe_algorithm)
        if self._algorithm is None:
            logging.warning('Unknown or unsupported algorithm: %s', self._path)
            return None
        logging.info('\tAlgorithm: %s', self._algorithm)
        return stub[0:-3]

    _RECOGNIZED_METHODS = ('GFSbox', 'KeySbox', 'VarKey', 'VarTxt')

    def _strip_method(self, stub):
        for method in self._RECOGNIZED_METHODS:
            if stub.endswith(method):
                logging.info('\tMethod: %s', method)
                return stub[0:len(stub) - len(method)]
        logging.warning('Unknown or unsupported method: %s', self._path)
        return None

    def _strip_mode(self, stub):
        self._mode = Mode.try_parse(stub)
        if self._mode is None:
            logging.warning('Unknown or unsupported mode: %s', self._path)
            return None
        logging.info('\tMode: %s', self._mode)
        return self._mode


class TestArchive(zipfile.ZipFile):
    def __init__(self, path):
        super().__init__(path)

    def enum_test_files(self):
        with TemporaryDirectory() as tmp_dir:
            for path in self.namelist():
                yield TestFile(self.extract(path, tmp_dir))


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


def run_tests(archive_path, tools_path=(), use_sde=False, use_boxes=False, log_path=None):
    _setup_logging(log_path)
    tools = Tools(tools_path, use_sde=use_sde)
    archive = TestArchive(archive_path)
    exit_codes = []

    for test_file in archive.enum_test_files():
        exit_codes.append(test_file.run_encryption_tests(tools, use_boxes))
        exit_codes.append(test_file.run_decryption_tests(tools, use_boxes))

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
    parser.add_argument('--archive', '-a', dest='archive_path', metavar='PATH',
                        default=os.path.join(_script_dir, 'data/KAT_AES.zip'),
                        help='set test vectors archive file path')
    parser.add_argument('--log', '-l', dest='log_path', metavar='PATH',
                        help='set log file path')
    return parser.parse_args(args)


def main(args=None):
    return run_tests(**vars(_parse_args(args)))


if __name__ == '__main__':
    sys.exit(main())

# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

from collections import OrderedDict
import configparser
from datetime import datetime
from enum import Enum
import logging
import os.path
import sys
from tempfile import TemporaryDirectory
import zipfile

from toolkit import *

class _MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(OrderedDict, self).__setitem__(key, value)

def verify_test_output(actual, expected):
    if len(actual) != len(expected):
        logging.error('Unexpected output length {0} (expected {1})'.format(len(actual), len(expected)))
        return False
    if actual != expected:
        logging.error('Expected output:\n' + '\n'.join(expected))
        return False
    return True

class TestExitCode(Enum):
    SUCCESS, FAILURE, ERROR, SKIPPED = range(1, 5)

class TestFile:
    def __init__(self, path):
        self._path = path
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
        except Exception as e:
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
        except Exception as e:
            logging.error('Encountered an exception!')
            logging.exception(e)
            return TestExitCode.ERROR

    def _parse_path(self):
        logging.info('Trying to parse test file path \'{0}\'...'.format(self._path))
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
            logging.warn('Unknown test vectors file extension \'{0}\'!'.format(self._path))
            return None
        return stub

    def _strip_algorithm(self, stub):
        key_size = stub[-3:]
        maybe_algorithm = 'aes{0}'.format(key_size)
        self._algorithm = Algorithm.try_parse(maybe_algorithm)
        if self._algorithm is not None:
            logging.info('\tAlgorithm: {0}'.format(self._algorithm))
            return stub[0:-3]
        else:
            logging.warn('Unknown or unsupported algorithm: ' + self._path)
            return None

    _RECOGNIZED_METHODS = ('GFSbox', 'KeySbox', 'VarKey', 'VarTxt')

    def _strip_method(self, stub):
        for method in self._RECOGNIZED_METHODS:
            if stub.endswith(method):
                logging.info('\tMethod: {0}'.format(method))
                return stub[0:len(stub) - len(method)]
        logging.warn('Unknown or unsupported method: ' + self._path)

    def _strip_mode(self, stub):
        self._mode = Mode.try_parse(stub)
        if self._mode is not None:
            logging.info('\tMode: {0}'.format(self._mode))
            return self._mode
        else:
            logging.warn('Unknown or unsupported mode: ' + self._path)
            return None

def _build_default_log_path():
    return datetime.now().strftime('{}_%Y-%m-%d_%H-%M-%S.log').format(
        os.path.splitext(os.path.basename(__file__))[0])

class TestArchive(zipfile.ZipFile):
    def __init__(self, path):
        super().__init__(path)

    def list_test_files(self):
        with TemporaryDirectory() as tmp_dir:
            for p in self.namelist():
                yield TestFile(self.extract(p, tmp_dir))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', '-p', nargs='*',
                        help='set path to block encryption utilities')
    parser.add_argument('--sde', '-e', action='store_true',
                        help='use Intel SDE to run *.exe files')
    parser.add_argument('--use-boxes', '-b', action='store_true',
                        help='use the "boxes" interface')
    parser.add_argument('--archive', '-a', default='KAT_AES.zip',
                        help='set path of the archive with the test vectors')
    parser.add_argument('--log', '-l', default=_build_default_log_path(),
                        help='set log file path')
    args = parser.parse_args()

    logging.basicConfig(filename=args.log,
                        format='%(asctime)s | %(module)s | %(levelname)s | %(message)s',
                        level=logging.DEBUG)

    tools = Tools(args.path, use_sde=args.sde)
    archive = TestArchive(args.archive)
    exit_codes = []

    for test_file in archive.list_test_files():
        exit_codes.append(test_file.run_encryption_tests(tools, args.use_boxes))
        exit_codes.append(test_file.run_decryption_tests(tools, args.use_boxes))

    logging.info('Test exit codes:')
    logging.info('\tSkipped:   {}'.format(exit_codes.count(TestExitCode.SKIPPED)))
    logging.info('\tError(s):  {}'.format(exit_codes.count(TestExitCode.ERROR)))
    logging.info('\tSucceeded: {}'.format(exit_codes.count(TestExitCode.SUCCESS)))
    logging.info('\tFailed:    {}'.format(exit_codes.count(TestExitCode.FAILURE)))
    if (exit_codes.count(TestExitCode.ERROR) == 0 and
            exit_codes.count(TestExitCode.FAILURE) == 0):
        sys.exit()
    else:
        sys.exit(1)

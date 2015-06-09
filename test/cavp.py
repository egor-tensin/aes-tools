# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

from collections import OrderedDict
import configparser
from datetime import datetime
import logging
import os.path
import toolkit
import zipfile

class _MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(OrderedDict, self).__setitem__(key, value)

def _gen_inputs(cls, keys, plaintexts, init_vectors):
    if init_vectors is None:
        init_vectors = [None for key in keys]
    for key, plaintext, iv in zip(keys, plaintexts, init_vectors):
        yield cls(key, [plaintext], iv)

def _gen_encryption_inputs(keys, plaintexts, init_vectors):
    return _gen_inputs(toolkit.EncryptionInput, keys, plaintexts, init_vectors)

def _gen_decryption_inputs(keys, ciphertexts, init_vectors):
    return _gen_inputs(toolkit.DecryptionInput, keys, ciphertexts, init_vectors)

def _split_into_chunks(expected_output, inputs, max_len=100):
    for i in range(0, len(inputs), max_len):
        yield expected_output[i:i+max_len], inputs[i:i+max_len]

def _assert_output(actual, expected):
    if len(actual) != len(expected):
        logging.error('Unexpected output length {0} (expected {1})'.format(len(actual), len(expected)))
        return False
    if actual != expected:
        logging.error('Expected output:\n' + '\n'.join(expected))
        return False
    return True

class _TestExitCode:
    SUCCESS, FAILURE, ERROR, SKIPPED = range(4)

class _TestVectorsFile:
    def __init__(self, path, archive):
        self._archive = archive
        self._path = path
        self._fn = os.path.split(path)[1]
        self._valid = False
        self._parse()

    def valid(self):
        return self._valid

    def algorithm(self):
        return self._algo

    def mode(self):
        return self._mode

    def parse(self):
        self._parser = configparser.ConfigParser(dict_type=_MultiOrderedDict,
                                                 strict=False,
                                                 interpolation=None,
                                                 empty_lines_in_values=False)
        self._parser.read_string(self._archive.read(self._path).decode('utf-8'))

    def _extract_test_data(self, section):
        keys = self._parser.get(section, 'key')
        plaintexts = self._parser.get(section, 'plaintext')
        ciphertexts = self._parser.get(section, 'ciphertext')
        init_vectors = None
        if toolkit.mode_requires_init_vector(self.mode()):
            init_vectors = self._parser.get(section, 'iv')
        return keys, plaintexts, ciphertexts, init_vectors

    def _run_tests(self, tool, inputs, expected_output):
        try:
            for expected_output_chunk, input_chunk in _split_into_chunks(expected_output, list(inputs)):
                actual_output = tool(self.algorithm(), self.mode(), input_chunk)
                if not _assert_output(actual_output, expected_output_chunk):
                    return _TestExitCode.FAILURE
            return _TestExitCode.SUCCESS
        except toolkit.ToolkitError as e:
            logging.error('Encountered an exception, skipping...')
            logging.exception(e)
            return _TestExitCode.ERROR

    def run_encryption_tests(self, tools):
        logging.info('Running encryption tests...')
        keys, plaintexts, ciphertexts, init_vectors = self._extract_test_data('ENCRYPT')
        inputs = _gen_encryption_inputs(keys, plaintexts, init_vectors)
        return self._run_tests(tools.run_encrypt_tool, inputs, ciphertexts)

    def run_decryption_tests(self, tools):
        logging.info('Running decryption tests...')
        keys, plaintexts, ciphertexts, init_vectors = self._extract_test_data('DECRYPT')
        inputs = _gen_decryption_inputs(keys, ciphertexts, init_vectors)
        return self._run_tests(tools.run_decrypt_tool, inputs, plaintexts)

    def _parse(self):
        logging.info('Trying to parse test vectors file name \'{0}\'...'.format(self._fn))
        stub = self._strip_extension(self._fn)
        if not stub: return
        stub = self._strip_algorithm(stub)
        if not stub: return
        stub = self._strip_method(stub)
        if not stub: return
        stub = self._strip_mode(stub)
        if not stub: return
        self._valid = True

    def _strip_extension(self, stub):
        stub, ext = os.path.splitext(stub)
        if ext != '.rsp':
            logging.warn('Unknown test vectors file extension \'{0}\'!'.format(self._fn))
            return None
        return stub

    def _strip_algorithm(self, stub):
        algo_size = stub[-3:]
        maybe_algo = 'aes{0}'.format(algo_size)
        self._algo = toolkit.to_supported_algorithm(maybe_algo)
        if self._algo:
            logging.info('\tAlgorithm: {0}'.format(self._algo))
            return stub[0:-3]
        else:
            logging.warn('Unknown or unsupported algorithm \'{0}\''.format(self._fn))
            return None

    def _strip_method(self, stub):
        for method in ('GFSbox', 'KeySbox', 'VarKey', 'VarTxt'):
            if stub.endswith(method):
                logging.info('\tMethod: {0}'.format(method))
                return stub[0:len(stub) - len(method)]
        logging.warn('Unknown or unsupported method \'{0}\''.format(self._fn))

    def _strip_mode(self, stub):
        self._mode = toolkit.to_supported_mode(stub)
        if self._mode:
            logging.info('\tMode: {0}'.format(self._mode))
            return self._mode
        else:
            logging.warn('Unknown or unsupported mode \'{0}\''.format(self._fn))
            return None

def _parse_test_vectors_archive(tools, archive_path='KAT_AES.zip'):
    archive = zipfile.ZipFile(archive_path)
    exit_codes = []
    for fn in archive.namelist():
        member = _TestVectorsFile(fn, archive)
        if member.valid():
            member.parse()
            exit_codes.append(member.run_encryption_tests(tools))
            exit_codes.append(member.run_decryption_tests(tools))
        else:
            exit_codes.append(_TestExitCode.SKIPPED)
    logging.info('Test exit codes:')
    logging.info('\tSkipped:   {0}'.format(exit_codes.count(_TestExitCode.SKIPPED)))
    logging.info('\tError(s):  {0}'.format(exit_codes.count(_TestExitCode.ERROR)))
    logging.info('\tSucceeded: {0}'.format(exit_codes.count(_TestExitCode.SUCCESS)))
    logging.info('\tFailed:    {0}'.format(exit_codes.count(_TestExitCode.FAILURE)))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', '-r', required=True,
                        help='set path to *.exe files')
    parser.add_argument('--sde', '-e', action='store_true',
                        help='use Intel SDE to run *.exe files')
    parser.add_argument('--log', '-l', help='set log file path')
    args = parser.parse_args()

    logging_options = {'format': '%(asctime)s | %(module)s | %(levelname)s | %(message)s',
                       'level': logging.DEBUG}
    if args.log is None:
        logging_options['filename'] = datetime.now().strftime('cavp_%Y-%m-%d_%H-%M-%S.log')
    else:
        logging_options['filename'] = args.log
    logging.basicConfig(**logging_options)

    tools = toolkit.Tools(args.root, use_sde=args.sde)
    _parse_test_vectors_archive(tools)

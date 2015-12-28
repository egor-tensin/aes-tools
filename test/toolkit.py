# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

import collections
import logging
import os.path
import subprocess

AES128, AES192, AES256 = 'aes128', 'aes192', 'aes256'
ECB, CBC, CFB, OFB, CTR = 'ecb', 'cbc', 'cfb', 'ofb', 'ctr'

_SUPPORTED_ALGORITHMS = AES128, AES192, AES256
_SUPPORTED_MODES = ECB, CBC, CFB, OFB, CTR

def get_supported_algorithms():
    return _SUPPORTED_ALGORITHMS

def get_supported_modes():
    return _SUPPORTED_MODES

def mode_requires_init_vector(mode):
    if mode not in _SUPPORTED_MODES:
        raise NotImplementedError('unsupported mode of operation ' + s)
    return mode != ECB

def to_supported_algorithm(s):
    algorithm = is_algorithm_supported(s)
    if algorithm is None:
        raise NotImplementedError('unsupported algorithm ' + s)
    return algorithm

def is_algorithm_supported(s):
    s = s.lower()
    if s in _SUPPORTED_ALGORITHMS:
        return s
    return None

def to_supported_mode(s):
    mode = is_mode_supported(s)
    if mode is None:
        raise NotImplementedError('unsupported mode ' + s)
    return mode

def is_mode_supported(s):
    s = s.lower()
    if s in _SUPPORTED_MODES:
        return s
    if s == CFB + '128':
        return CFB
    return None

class BlockInput:
    def __init__(self, key, plaintexts, iv=None):
        self.key = key
        self.plaintexts = plaintexts
        self.iv = iv

    def to_args(self):
        args = [self.key]
        if self.iv is not None:
            args.append(self.iv)
        args.extend(self.plaintexts)
        return args

class Tools:
    def __init__(self, search_dirs, use_sde=False):
        if search_dirs:
            if isinstance(search_dirs, str):
                os.environ['PATH'] += os.pathsep + search_dirs
            elif isinstance(search_dirs, collections.Iterable):
                os.environ['PATH'] += os.pathsep + os.pathsep.join(search_dirs)
            else:
                os.environ['PATH'] += os.pathsep + str(search_dirs)
        self._use_sde = use_sde
        self._logger = logging.getLogger(__name__)

    _ENCRYPT_BLOCK = 'encrypt_block.exe'
    _DECRYPT_BLOCK = 'decrypt_block.exe'
    _ENCRYPT_FILE = 'encrypt_file.exe'
    _DECRYPT_FILE = 'decrypt_file.exe'

    def run(self, tool_path, args):
        cmd_list = ['sde', '--', tool_path] if self._use_sde else [tool_path]
        cmd_list.extend(args)
        logging.info('Trying to execute: {0}'.format(
            subprocess.list2cmdline(cmd_list)))
        try:
            output = subprocess.check_output(
                cmd_list, universal_newlines=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            logging.error('Output:\n' + e.output)
            raise
        logging.info('Output:\n' + output)
        return output.split()

    @staticmethod
    def _block_inputs_to_args(inputs):
        args = []
        while True:
            head = next(inputs, None)
            if head is None:
                break
            args.append('--')
            args.extend(head.to_args())
        return args

    @staticmethod
    def _block_settings_to_args(algorithm, mode, use_boxes=False):
        args = [
            '--algorithm', algorithm,
            '--mode', mode,
        ]
        if use_boxes:
            args.append('--use-boxes')
        return args

    @staticmethod
    def _build_block_args(algorithm, mode, inputs, use_boxes=False):
        args = Tools._block_settings_to_args(algorithm, mode, use_boxes)
        if isinstance(inputs, collections.Iterable):
            args.extend(Tools._block_inputs_to_args(iter(inputs)))
        else:
            args.extend(inputs.to_args())
        return args

    def run_encrypt_block(self, algorithm, mode, inputs, use_boxes=False):
        return self.run(self._ENCRYPT_BLOCK,
                        self._build_block_args(algorithm, mode, inputs, use_boxes))

    def run_decrypt_block(self, algorithm, mode, inputs, use_boxes=False):
        return self.run(self._DECRYPT_BLOCK,
                        self._build_block_args(algorithm, mode, inputs, use_boxes))

    @staticmethod
    def _file_settings_to_args(algorithm, mode, key, input_path, output_path, iv=None):
        args = [
            '--algorithm', algorithm,
            '--mode', mode,
            '--key', key,
            '--input-path', input_path,
            '--output-path', output_path
        ]
        if mode_requires_init_vector(mode):
            if not iv:
                raise ValueError('mode \'{}\' requires initialization vector'.format(mode))
            args.extend(('--iv', iv))
        return args

    def run_encrypt_file(self, algorithm, mode, key, input_path, output_path, iv=None):
        return self.run(self._ENCRYPT_FILE,
                        self._file_settings_to_args(algorithm, mode, key, input_path, output_path, iv))

    def run_decrypt_file(self, algorithm, mode, key, input_path, output_path, iv=None):
        return self.run(self._DECRYPT_FILE,
                        self._file_settings_to_args(algorithm, mode, key, input_path, output_path, iv))

# Copyright (c) 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is part of the "AES tools" project.
# For details, see https://github.com/egor-tensin/aes-tools.
# Distributed under the MIT License.

import collections
from enum import Enum
import logging
import os.path
import subprocess

class Algorithm(Enum):
    @staticmethod
    def parse(s):
        return Algorithm(s.lower())

    @staticmethod
    def try_parse(s):
        try:
            return Algorithm.parse(s)
        except ValueError:
            return None

    AES128, AES192, AES256 = 'aes128', 'aes192', 'aes256'

    def __str__(self):
        return self.value


class Mode(Enum):
    @staticmethod
    def parse(s):
        s = s.lower()
        if '{}128'.format(Mode.CFB) == s:
            return Mode.CFB
        return Mode(s)

    @staticmethod
    def try_parse(s):
        try:
            return Mode.parse(s)
        except ValueError:
            return None

    ECB, CBC, CFB, OFB, CTR = 'ecb', 'cbc', 'cfb', 'ofb', 'ctr'

    def requires_init_vector(self):
        return self != Mode.ECB

    def __str__(self):
        return self.value

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

    _ENCRYPT_BLOCK = 'encrypt_block'
    _DECRYPT_BLOCK = 'decrypt_block'
    _ENCRYPT_FILE = 'encrypt_file'
    _DECRYPT_FILE = 'decrypt_file'

    def run(self, tool_path, args):
        cmd_list = ['sde', '--', tool_path] if self._use_sde else [tool_path]
        cmd_list.extend(args)
        logging.info('Trying to execute: ' + subprocess.list2cmdline(cmd_list))
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
            '--algorithm', str(algorithm),
            '--mode', str(mode),
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
            '--algorithm', str(algorithm),
            '--mode', str(mode),
            '--key', key,
            '--input-path', input_path,
            '--output-path', output_path
        ]
        if iv is not None:
            args.extend(('--iv', iv))
        return args

    def run_encrypt_file(self, algorithm, mode, key, input_path, output_path, iv=None):
        return self.run(self._ENCRYPT_FILE,
                        self._file_settings_to_args(algorithm, mode, key, input_path, output_path, iv))

    def run_decrypt_file(self, algorithm, mode, key, input_path, output_path, iv=None):
        return self.run(self._DECRYPT_FILE,
                        self._file_settings_to_args(algorithm, mode, key, input_path, output_path, iv))

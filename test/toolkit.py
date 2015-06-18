# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

import collections
import logging
import os.path
import subprocess
import sys

AES128, AES192, AES256 = 'aes128', 'aes192', 'aes256'
ECB, CBC, CFB, OFB, CTR = 'ecb', 'cbc', 'cfb', 'ofb', 'ctr'

_supported_algorithms = AES128, AES192, AES256
_supported_modes = ECB, CBC, CFB, OFB, CTR

def get_supported_algorithms():
    return _supported_algorithms

def get_supported_modes():
    return _supported_modes

def mode_requires_init_vector(mode):
    return mode != ECB

def to_supported_algorithm(s):
    s = s.lower()
    if s in _supported_algorithms:
        return s
    return None

def to_supported_mode(s):
    s = s.lower()
    if s in _supported_modes:
        return s
    if s == CFB + '128':
        return CFB
    return None

class EncryptionInput:
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

class DecryptionInput:
    def __init__(self, key, ciphertexts, iv=None):
        self.key = key
        self.ciphertexts = ciphertexts
        self.iv = iv

    def to_args(self):
        args = [self.key]
        if self.iv is not None:
            args.append(self.iv)
        args.extend(self.ciphertexts)
        return args

class ToolkitError(RuntimeError):
    pass

class Tools:
    def __init__(self, root_dir_path, use_sde=False):
        self._root_dir_path = root_dir_path
        self._use_sde = use_sde
        self._logger = logging.getLogger(__name__)

    def _get_tool_path(self, fn):
        return os.path.join(self._root_dir_path, fn)

    def get_encrypt_tool_path(self):
        return self._get_tool_path('encrypt_block_aes.exe')

    def get_decrypt_tool_path(self):
        return self._get_tool_path('decrypt_block_aes.exe')

    def run_tool(self, tool_path, algo, mode, args):
        cmd_list = ['sde', '--', tool_path] if self._use_sde else [tool_path]
        cmd_list.extend(('-a', algo, '-m', mode, '--'))
        cmd_list.extend(args)
        logging.info('Trying to execute: {0}'.format(subprocess.list2cmdline(cmd_list)))
        try:
            output = subprocess.check_output(cmd_list, universal_newlines=True)
        except subprocess.CalledProcessError as e:
            logging.exception(e)
            raise ToolkitError() from e
        logging.info('Output:\n' + output)
        return output.split()

    @staticmethod
    def _inputs_to_args(inputs):
        head = next(inputs, None)
        if head is None:
            return []
        args = head.to_args()
        while True:
            tail = next(inputs, None)
            if tail is None:
                break
            args.append('--')
            args.extend(tail.to_args())
        return args

    def run_encrypt_tool(self, algo, mode, inputs):
        if isinstance(inputs, collections.Iterable):
            args = self._inputs_to_args(iter(inputs))
        else:
            args = inputs.to_args()
        return self.run_tool(self.get_encrypt_tool_path(), algo, mode, args)

    def run_decrypt_tool(self, algo, mode, inputs):
        if isinstance(inputs, collections.Iterable):
            args = self._inputs_to_args(iter(inputs))
        else:
            args = inputs.to_args()
        return self.run_tool(self.get_decrypt_tool_path(), algo, mode, args)

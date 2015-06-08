# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

import logging
import os.path
import subprocess
import sys

AES128, AES192, AES256 = 'aes128', 'aes192', 'aes256'
ECB, CBC, CFB, OFB, CTR = 'ecb', 'cbc', 'cfb', 'ofb', 'ctr'

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

class Tools:
    def __init__(self, root_dir_path, use_sde=False):
        self._root_dir_path = root_dir_path
        self._use_sde = use_sde
        self._logger = logging.getLogger(__name__)

    def _get_tool_path(self, fn):
        return os.path.join(self._root_dir_path, fn)

    def get_encrypt_tool_path(self, algo, mode):
        return self._get_tool_path('{0}{1}_encrypt.exe'.format(algo, mode))

    def get_decrypt_tool_path(self, algo, mode):
        return self._get_tool_path('{0}{1}_decrypt.exe'.format(algo, mode))

    def run_tool(self, tool_path, args):
        cmd_list = ['sde', '--', tool_path] if self._use_sde else [tool_path]
        cmd_list.extend(args)
        logging.info('Trying to execute: {0}'.format(subprocess.list2cmdline(cmd_list)))
        output = subprocess.check_output(cmd_list, universal_newlines=True)
        logging.info('Output:\n' + output)
        return output.split()

    def run_encrypt_tool(self, algo, mode, input):
        return self.run_tool(self.get_encrypt_tool_path(algo, mode), input.to_args())

    def run_decrypt_tool(self, algo, mode, input):
        return self.run_tool(self.get_decrypt_tool_path(algo, mode), input.to_args())

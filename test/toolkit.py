# Copyright 2015 Egor Tensin <Egor.Tensin@gmail.com>
# This file is licensed under the terms of the MIT License.
# See LICENSE.txt for details.

import os.path
import subprocess
import sys

class Tools:
    def __init__(self, root_dir_path, use_sde=False):
        self._root_dir_path = root_dir_path
        self._use_sde = use_sde

    def _get_tool_path(self, tool_name):
        return os.path.join(self._root_dir_path, tool_name)

    def _get_encrypt_tool_path(self, prefix):
        return self._get_tool_path('{0}_encrypt.exe'.format(prefix))

    def _get_decrypt_tool_path(self, prefix):
        return self._get_tool_path('{0}_decrypt.exe'.format(prefix))

    def _capture_tool_output(self, tool_path, args):
        with_sde = ['sde', '--', tool_path] if self._use_sde else [tool_path]
        return subprocess.check_output(with_sde + args, universal_newlines=True).split()

    def encrypt(self, prefix, key, args):
        print('Encrypting using \'{0}\'...'.format(prefix))
        print('\tKey:', key)
        return self._capture_tool_output(self._get_encrypt_tool_path(prefix), [key] + args)

    def decrypt(self, prefix, key, args):
        print('Decrypting using \'{0}\'...'.format(prefix))
        print('\tKey:', key)
        return self._capture_tool_output(self._get_decrypt_tool_path(prefix), [key] + args)

    def encrypt_with_iv(self, prefix, key, iv, args):
        print('Encrypting using \'{0}\'...'.format(prefix))
        print('\tKey:', key)
        print('\tInitialization vector:', iv)
        return self._capture_tool_output(self._get_encrypt_tool_path(prefix), [key, iv] + args)

    def decrypt_with_iv(self, prefix, key, iv, args):
        print('Decrypting using \'{0}\'...'.format(prefix))
        print('\tKey:', key)
        print('\tInitialization vector:', iv)
        return self._capture_tool_output(self._get_decrypt_tool_path(prefix), [key, iv] + args)

    def detect_mismatches(self, input, actual_output, expected_output):
        if len(actual_output) != len(expected_output):
            print('Unexpected output length!', file=sys.stderr)
            print('\tExpected length:', len(expected_output), file=sys.stderr)
            print('\tActual length:', len(actual_output), file=sys.stderr)
            return False
        no_mismatches = True
        for i in range(len(input)):
            if actual_output[i] != expected_output[i]:
                print('A mismatch detected!', file=sys.stderr)
                print('\tInput:', input[i], file=sys.stderr)
                print('\tExpected:', expected_output[i], file=sys.stderr)
                print('\tActual:', actual_output[i], file=sys.stderr)
                no_mismatches = False
        return no_mismatches

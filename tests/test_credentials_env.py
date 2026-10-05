"""Credentials come from the environment, not from files committed to the repository."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs

import credentials
from protocol import UpstreamError

ROWS = '123 br-pass BR\n456 vn-pass VN\n789 global-pass GLOBAL\n'


class EnvAccountsTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for key in list(os.environ):
            if key == 'FREEFIRE_ACCOUNTS' or (key.startswith('FREEFIRE_') and key.endswith(('_UID', '_PASSWORD'))):
                os.environ.pop(key)
        self.tmp = Path(tempfile.mkdtemp()) / 'accounts.txt'
        patcher = mock.patch.object(credentials, 'ACCOUNTS_FILE', self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def uid(self, region):
        return parse_qs(credentials.get_credentials(region))['uid'][0]

    def test_rows_from_environment_variable(self):
        with mock.patch.dict(os.environ, {'FREEFIRE_ACCOUNTS': ROWS}):
            self.assertEqual(self.uid('BR'), '123')
            self.assertEqual(self.uid('US'), '123')      # BR group fallback
            self.assertEqual(self.uid('VN'), '456')
            self.assertEqual(self.uid('BD'), '789')      # GLOBAL group

    def test_literal_backslash_n_separator(self):
        with mock.patch.dict(os.environ, {'FREEFIRE_ACCOUNTS': r'123 br-pass BR\n456 vn-pass VN'}):
            self.assertEqual(self.uid('VN'), '456')

    def test_environment_rows_win_over_local_file(self):
        self.tmp.write_text('999 file-pass BR\n')
        with mock.patch.dict(os.environ, {'FREEFIRE_ACCOUNTS': ROWS}):
            self.assertEqual(self.uid('BR'), '123')

    def test_local_file_still_works_when_env_not_set(self):
        self.tmp.write_text('999 file-pass BR\n')
        self.assertEqual(self.uid('BR'), '999')

    def test_nothing_configured_fails_with_helpful_message(self):
        with self.assertRaises(UpstreamError) as ctx:
            credentials.get_credentials('BR')
        self.assertEqual(ctx.exception.code, 'CREDENTIAL_CONFIG_ERROR')
        self.assertIn('FREEFIRE_ACCOUNTS', str(ctx.exception))

    def test_per_region_override_still_beats_accounts_variable(self):
        with mock.patch.dict(os.environ, {'FREEFIRE_ACCOUNTS': ROWS, 'FREEFIRE_BR_UID': '222',
                                          'FREEFIRE_BR_PASSWORD': 'override'}):
            self.assertEqual(self.uid('BR'), '222')

    def test_bad_rows_fail_without_leaking_the_password(self):
        for bad in ('123 supersecret UNKNOWN', '123 supersecret extra BR', '1 a BR\n2 supersecret BR'):
            with mock.patch.dict(os.environ, {'FREEFIRE_ACCOUNTS': bad}):
                with self.assertRaises(UpstreamError) as ctx:
                    credentials.get_credentials('BR')
                self.assertNotIn('supersecret', str(ctx.exception))

    def test_password_files_are_git_ignored_and_example_has_no_real_values(self):
        root = Path(__file__).resolve().parent.parent
        ignored = (root / '.gitignore').read_text().split()
        self.assertIn('accounts.txt', ignored)
        self.assertIn('accounts-legacy.txt', ignored)
        self.assertFalse((root / 'accounts-legacy.txt').exists())
        example = (root / 'accounts.example.txt').read_text()
        self.assertIn('replace-with-password', example)


if __name__ == '__main__':
    unittest.main()

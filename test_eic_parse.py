#!/usr/bin/env python3

"""
Unit tests for eic_parse.py
Tests argument parsing and other functions as they are implemented.
"""

import unittest
import sys
from unittest.mock import patch
from eic_parse import str_to_bool, parse_arguments
import argparse


class TestStrToBool(unittest.TestCase):
    """Test the str_to_bool converter function."""

    def test_true_lowercase(self):
        """Test 'true' converts to True."""
        self.assertEqual(str_to_bool('true'), True)

    def test_true_uppercase(self):
        """Test 'TRUE' converts to True."""
        self.assertEqual(str_to_bool('TRUE'), True)

    def test_true_mixedcase(self):
        """Test 'TrUe' converts to True."""
        self.assertEqual(str_to_bool('TrUe'), True)

    def test_false_lowercase(self):
        """Test 'false' converts to False."""
        self.assertEqual(str_to_bool('false'), False)

    def test_false_uppercase(self):
        """Test 'FALSE' converts to False."""
        self.assertEqual(str_to_bool('FALSE'), False)

    def test_false_mixedcase(self):
        """Test 'FaLsE' converts to False."""
        self.assertEqual(str_to_bool('FaLsE'), False)

    def test_invalid_value(self):
        """Test invalid value raises ArgumentTypeError."""
        with self.assertRaises(argparse.ArgumentTypeError):
            str_to_bool('yes')

        with self.assertRaises(argparse.ArgumentTypeError):
            str_to_bool('no')

        with self.assertRaises(argparse.ArgumentTypeError):
            str_to_bool('1')

        with self.assertRaises(argparse.ArgumentTypeError):
            str_to_bool('maybe')


class TestParseArguments(unittest.TestCase):
    """Test the parse_arguments function."""

    def test_all_required_args(self):
        """Test parsing with all required arguments provided."""
        test_args = [
            'eic_parse.py',
            '-x', 'true',
            '-p', '/tmp/keys',
            '-o', '/usr/bin/openssl',
            '-d', '/dev/shm/eic-test',
            '-s', 'CERT_CHAIN_HERE',
            '-i', 'i-1234567890abcdef0',
            '-c', 'managed-ssh-signer.us-east-1.amazonaws.com',
            '-a', '/etc/ssl/certs',
            '-v', '/dev/shm/eic-ocsp'
        ]

        with patch.object(sys, 'argv', test_args):
            args = parse_arguments()

            self.assertEqual(args.is_debug, True)
            self.assertEqual(args.keys_path, '/tmp/keys')
            self.assertEqual(args.openssl, '/usr/bin/openssl')
            self.assertEqual(args.tmpdir, '/dev/shm/eic-test')
            self.assertEqual(args.signer, 'CERT_CHAIN_HERE')
            self.assertEqual(args.current_instance_id, 'i-1234567890abcdef0')
            self.assertEqual(args.expected_cn, 'managed-ssh-signer.us-east-1.amazonaws.com')
            self.assertEqual(args.ca_path, '/etc/ssl/certs')
            self.assertEqual(args.ocsp_dir_path, '/dev/shm/eic-ocsp')
            self.assertEqual(args.expected_key, None)

    def test_with_optional_fingerprint(self):
        """Test parsing with optional fingerprint argument."""
        test_args = [
            'eic_parse.py',
            '-x', 'false',
            '-p', '/tmp/keys',
            '-o', '/usr/bin/openssl',
            '-d', '/dev/shm/eic-test',
            '-s', 'CERT_CHAIN_HERE',
            '-i', 'i-1234567890abcdef0',
            '-c', 'managed-ssh-signer.us-east-1.amazonaws.com',
            '-a', '/etc/ssl/certs',
            '-v', '/dev/shm/eic-ocsp',
            '-f', 'SHA256:abcdef1234567890'
        ]

        with patch.object(sys, 'argv', test_args):
            args = parse_arguments()

            self.assertEqual(args.is_debug, False)
            self.assertEqual(args.expected_key, 'SHA256:abcdef1234567890')

    def test_missing_required_arg(self):
        """Test that missing required argument causes exit."""
        test_args = [
            'eic_parse.py',
            '-x', 'true',
            '-p', '/tmp/keys'
            # Missing other required args
        ]

        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit):
                parse_arguments()

    def test_invalid_debug_value(self):
        """Test that invalid debug value causes exit."""
        test_args = [
            'eic_parse.py',
            '-x', 'yes',  # Invalid - should be true/false
            '-p', '/tmp/keys',
            '-o', '/usr/bin/openssl',
            '-d', '/dev/shm/eic-test',
            '-s', 'CERT_CHAIN_HERE',
            '-i', 'i-1234567890abcdef0',
            '-c', 'managed-ssh-signer.us-east-1.amazonaws.com',
            '-a', '/etc/ssl/certs',
            '-v', '/dev/shm/eic-ocsp'
        ]

        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit):
                parse_arguments()


if __name__ == '__main__':
    unittest.main()

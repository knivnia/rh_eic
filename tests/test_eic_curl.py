#!/usr/bin/env python3

import base64
import os
import sys
import tempfile
import unittest
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

# ---------------------------------------------------------------------------
# Import the module under test.  We patch syslog at import time so that the
# module-level ``log_info`` never writes to the real system log.
# ---------------------------------------------------------------------------
with patch('syslog.syslog'):
    from ec2_instance_connect_rhel import eic_curl


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _imds_response(data: str):
    """Return a context-manager mock that behaves like ``urlopen`` response."""
    resp = MagicMock()
    resp.read.return_value = data.encode('utf-8')
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _imds_response_bytes(data: bytes):
    resp = MagicMock()
    resp.read.return_value = data
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestExtractRegionFromAz(unittest.TestCase):
    """Pure function -- no mocking needed."""

    def test_standard_regions(self):
        cases = [
            ('us-east-1a', 'us-east-1'),
            ('us-west-2b', 'us-west-2'),
            ('eu-west-1c', 'eu-west-1'),
            ('ap-southeast-2a', 'ap-southeast-2'),
        ]
        for az, expected in cases:
            with self.subTest(az=az):
                self.assertEqual(eic_curl.extract_region_from_az(az), expected)

    def test_gov_and_china_regions(self):
        self.assertEqual(eic_curl.extract_region_from_az('us-gov-west-1a'),
                         'us-gov-west-1')
        self.assertEqual(eic_curl.extract_region_from_az('cn-north-1b'),
                         'cn-north-1')

    def test_invalid_az_returns_none(self):
        self.assertIsNone(eic_curl.extract_region_from_az(''))
        self.assertIsNone(eic_curl.extract_region_from_az('not-a-zone'))
        self.assertIsNone(eic_curl.extract_region_from_az('123'))


class TestCheckUserExists(unittest.TestCase):

    @patch('pwd.getpwnam')
    def test_existing_user(self, mock_pw):
        mock_pw.return_value = MagicMock()
        self.assertTrue(eic_curl.check_user_exists('ec2-user'))

    @patch('pwd.getpwnam', side_effect=KeyError('no such user'))
    def test_missing_user(self, _mock_pw):
        self.assertFalse(eic_curl.check_user_exists('nonexistent'))


class TestVerifyInstanceId(unittest.TestCase):

    def test_valid_ids(self):
        self.assertTrue(eic_curl.verify_instance_id('i-1234567890abcdef0'))
        self.assertTrue(eic_curl.verify_instance_id('i-abcdef01'))

    def test_invalid_ids(self):
        self.assertFalse(eic_curl.verify_instance_id(None))
        self.assertFalse(eic_curl.verify_instance_id(''))
        self.assertFalse(eic_curl.verify_instance_id('i-UPPER'))
        self.assertFalse(eic_curl.verify_instance_id('not-an-id'))
        self.assertFalse(eic_curl.verify_instance_id(12345))


class TestFetchToken(unittest.TestCase):

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_success(self, mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('tok-abc123')
        token = eic_curl.fetch_token()
        self.assertEqual(token, 'tok-abc123')

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_empty_token_exits_255(self, mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('')
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.fetch_token()
        self.assertEqual(ctx.exception.code, 255)

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen', side_effect=eic_curl.URLError('unreachable'))
    def test_urlerror_exits_255(self, _mock_urlopen, _mock_syslog):
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.fetch_token()
        self.assertEqual(ctx.exception.code, 255)


class TestFetchInstanceId(unittest.TestCase):

    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_success(self, mock_urlopen):
        mock_urlopen.return_value = _imds_response('i-abcdef0123456789')
        result = eic_curl.fetch_instance_id('http://imds/instance-id/', 'tok')
        self.assertEqual(result, 'i-abcdef0123456789')

    @patch('ec2_instance_connect_rhel.eic_curl.urlopen', side_effect=eic_curl.URLError('err'))
    def test_failure_returns_none(self, _mock):
        result = eic_curl.fetch_instance_id('http://imds/instance-id/', 'tok')
        self.assertIsNone(result)


class TestVerifyEc2Instance(unittest.TestCase):
    """Test the Xen / Nitro / non-EC2 detection branches."""

    @patch('syslog.syslog')
    @patch('builtins.open', mock_open(read_data='ec2abcdef-uuid'))
    @patch('os.path.isfile')
    def test_xen_valid(self, mock_isfile, _mock_syslog):
        mock_isfile.side_effect = lambda p: 'hypervisor/uuid' in p
        # Should return without exiting
        eic_curl.verify_ec2_instance('i-1234567890abcdef0')

    @patch('syslog.syslog')
    @patch('builtins.open', mock_open(read_data='not-ec2-uuid'))
    @patch('os.path.isfile')
    def test_xen_invalid_uuid(self, mock_isfile, _mock_syslog):
        mock_isfile.side_effect = lambda p: 'hypervisor/uuid' in p
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.verify_ec2_instance('i-1234567890abcdef0')
        self.assertEqual(ctx.exception.code, 0)

    @patch('syslog.syslog')
    @patch('builtins.open', mock_open(read_data='i-1234567890abcdef0'))
    @patch('os.path.isfile')
    def test_nitro_valid(self, mock_isfile, _mock_syslog):
        mock_isfile.side_effect = lambda p: 'board_asset_tag' in p
        eic_curl.verify_ec2_instance('i-1234567890abcdef0')

    @patch('syslog.syslog')
    @patch('builtins.open', mock_open(read_data='i-WRONGID'))
    @patch('os.path.isfile')
    def test_nitro_mismatch(self, mock_isfile, _mock_syslog):
        mock_isfile.side_effect = lambda p: 'board_asset_tag' in p
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.verify_ec2_instance('i-1234567890abcdef0')
        self.assertEqual(ctx.exception.code, 0)

    @patch('syslog.syslog')
    @patch('os.path.isfile', return_value=False)
    def test_no_ec2_files(self, _mock_isfile, _mock_syslog):
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.verify_ec2_instance('i-1234567890abcdef0')
        self.assertEqual(ctx.exception.code, 0)


class TestCheckActiveKeys(unittest.TestCase):

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_keys_present(self, mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('')
        self.assertTrue(eic_curl.check_active_keys('testuser', 'tok'))

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_404_exits_0(self, mock_urlopen, _mock_syslog):
        mock_urlopen.side_effect = eic_curl.HTTPError(
            'url', 404, 'Not Found', {}, None)
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.check_active_keys('testuser', 'tok')
        self.assertEqual(ctx.exception.code, 0)


class TestFetchAndValidateAz(unittest.TestCase):

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_valid_az(self, mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('us-east-1a')
        self.assertEqual(eic_curl.fetch_and_validate_az('tok'), 'us-east-1a')

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_invalid_az_exits_255(self, mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('INVALID-ZONE')
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.fetch_and_validate_az('tok')
        self.assertEqual(ctx.exception.code, 255)


class TestFetchAndValidateDomain(unittest.TestCase):

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_valid_domain(self, mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('amazonaws.com')
        self.assertEqual(
            eic_curl.fetch_and_validate_domain('tok'), 'amazonaws.com')

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_invalid_domain_exits_255(self, mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('evil.com')
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.fetch_and_validate_domain('tok')
        self.assertEqual(ctx.exception.code, 255)

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_china_domain(self, mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('amazonaws.com.cn')
        self.assertEqual(
            eic_curl.fetch_and_validate_domain('tok'), 'amazonaws.com.cn')


class TestFetchSignerCert(unittest.TestCase):

    @patch('syslog.syslog')
    def test_empty_region_exits_255(self, _mock_syslog):
        for region in (None, ''):
            with self.subTest(region=region):
                with self.assertRaises(SystemExit) as ctx:
                    eic_curl.fetch_signer_cert(region, 'amazonaws.com', 'tok')
                self.assertEqual(ctx.exception.code, 255)

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    @patch('ec2_instance_connect_rhel.eic_curl.register_temp_dir')
    def test_success(self, _mock_register, mock_urlopen, _mock_syslog):
        cert_pem = '-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----'
        mock_urlopen.return_value = _imds_response(cert_pem)
        with tempfile.TemporaryDirectory() as userpath:
            with patch('tempfile.mkdtemp', return_value=userpath):
                signer, path, cert_path = eic_curl.fetch_signer_cert(
                    'us-east-1', 'amazonaws.com', 'tok')
            self.assertEqual(signer,
                             'managed-ssh-signer.us-east-1.amazonaws.com')
            self.assertEqual(path, userpath)
            self.assertEqual(cert_path,
                             os.path.join(userpath, 'signer-cert.pem'))
            with open(cert_path) as f:
                self.assertEqual(f.read().strip(), cert_pem)

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    @patch('ec2_instance_connect_rhel.eic_curl.register_temp_dir')
    def test_uses_default_temp_dir_not_dev_shm(self, _mock_register,
                                             mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response(
            '-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----')
        with tempfile.TemporaryDirectory() as userpath:
            with patch('tempfile.mkdtemp', return_value=userpath) as mock_mkdtemp:
                eic_curl.fetch_signer_cert('us-east-1', 'amazonaws.com', 'tok')
                mock_mkdtemp.assert_called_once_with(prefix='eic-')
                self.assertNotIn('dir', mock_mkdtemp.call_args.kwargs)

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    @patch('tempfile.mkdtemp', return_value='/tmp/eic-test')
    @patch('ec2_instance_connect_rhel.eic_curl.register_temp_dir')
    def test_empty_cert_exits_1(self, _mock_register, _mock_mkdtemp,
                                mock_urlopen, _mock_syslog):
        mock_urlopen.return_value = _imds_response('')
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.fetch_signer_cert('us-east-1', 'amazonaws.com', 'tok')
        self.assertEqual(ctx.exception.code, 1)


class TestFetchOcspStaples(unittest.TestCase):

    @patch('syslog.syslog')
    @patch('os.chmod')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_fetches_and_writes_staples(self, mock_urlopen, _mock_chmod,
                                       _mock_syslog):
        staple_data = base64.b64encode(b'OCSP_DATA').decode()

        def urlopen_router(request, timeout=None):
            url = request.get_full_url()
            if url.endswith('signer-ocsp/'):
                return _imds_response('staple1')
            if 'signer-ocsp/staple1' in url:
                return _imds_response(staple_data)
            return _imds_response('')

        mock_urlopen.side_effect = urlopen_router

        with tempfile.TemporaryDirectory() as userpath:
            ocsp_path = eic_curl.fetch_ocsp_staples(userpath, 'tok')
            self.assertTrue(os.path.isdir(ocsp_path))
            staple_file = os.path.join(ocsp_path, 'staple1')
            self.assertTrue(os.path.isfile(staple_file))
            with open(staple_file, 'rb') as f:
                self.assertEqual(f.read(), b'OCSP_DATA')


class TestFetchSshKeys(unittest.TestCase):

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    def test_writes_keys_file(self, mock_urlopen, _mock_syslog):
        key_data = 'ssh-rsa AAAA testkey\nsig==\n'
        mock_urlopen.return_value = _imds_response(key_data)

        with tempfile.TemporaryDirectory() as userpath:
            keys_file = eic_curl.fetch_ssh_keys('testuser', userpath, 'tok')
            self.assertTrue(os.path.isfile(keys_file))
            with open(keys_file) as f:
                self.assertEqual(f.read(), key_data)


class TestCallParser(unittest.TestCase):

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_parse.run', return_value=0)
    def test_calls_eic_parse_and_exits(self, mock_run, _mock_syslog):
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.call_parser(
                '/tmp/keys', '/tmp/dir', '/tmp/signer-cert.pem', 'i-abc',
                'signer.us-east-1.amazonaws.com',
                eic_curl.CA_BUNDLE, '/tmp/ocsp')

        self.assertEqual(ctx.exception.code, 0)
        mock_run.assert_called_once()
        self.assertEqual(mock_run.call_args.kwargs['signer_path'],
                         '/tmp/signer-cert.pem')

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_parse.run', return_value=255)
    def test_propagates_parser_exit_code(self, mock_run, _mock_syslog):
        with self.assertRaises(SystemExit) as ctx:
            eic_curl.call_parser(
                '/tmp/keys', '/tmp/dir', '/tmp/signer-cert.pem', 'i-abc',
                'signer.us-east-1.amazonaws.com',
                eic_curl.CA_BUNDLE, '/tmp/ocsp')

        self.assertEqual(ctx.exception.code, 255)

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_parse.run', return_value=0)
    def test_fingerprint_passed_when_provided(self, mock_run, _mock_syslog):
        with self.assertRaises(SystemExit):
            eic_curl.call_parser(
                '/tmp/keys', '/tmp/dir', '/tmp/signer-cert.pem', 'i-abc',
                'signer.us-east-1.amazonaws.com',
                eic_curl.CA_BUNDLE, '/tmp/ocsp',
                fingerprint='SHA256:abcdef')

        self.assertEqual(mock_run.call_args.kwargs['expected_key'],
                         'SHA256:abcdef')


class TestMainIntegration(unittest.TestCase):
    """Integration test: exercise main() with all external calls mocked."""

    @patch('syslog.syslog')
    @patch('ec2_instance_connect_rhel.eic_parse.run', return_value=0)
    @patch('ec2_instance_connect_rhel.eic_curl.urlopen')
    @patch('tempfile.mkdtemp')
    @patch('ec2_instance_connect_rhel.eic_curl.register_temp_dir')
    @patch('os.chmod')
    @patch('pwd.getpwnam')
    @patch('os.path.isfile')
    @patch('builtins.open', new_callable=mock_open,
           read_data='i-1234567890abcdef0')
    @patch('os.umask')
    def test_nitro_happy_path(self, _mock_umask, mock_fopen,
                              mock_isfile, mock_pwd, mock_chmod,
                              _mock_register, mock_mkdtemp,
                              mock_urlopen, mock_parse_run,
                              _mock_syslog):
        """Full happy-path for a Nitro instance (no real I/O)."""
        # -- filesystem stubs --
        mock_isfile.side_effect = lambda p: 'board_asset_tag' in p
        tmpdir = tempfile.mkdtemp()
        mock_mkdtemp.return_value = tmpdir

        cert_pem = ('-----BEGIN CERTIFICATE-----\n'
                     'MOCK\n'
                     '-----END CERTIFICATE-----')
        staple_b64 = base64.b64encode(b'STAPLE').decode()

        def urlopen_router(request, timeout=None):
            url = request.get_full_url()
            if 'api/token' in url:
                return _imds_response('tok')
            if 'instance-id' in url:
                return _imds_response('i-1234567890abcdef0')
            if 'active-keys' in url:
                return _imds_response('')
            if 'availability-zone' in url:
                return _imds_response('us-east-1a')
            if 'services/domain' in url:
                return _imds_response('amazonaws.com')
            if 'signer-cert' in url:
                return _imds_response(cert_pem)
            if url.endswith('signer-ocsp/'):
                return _imds_response('s1')
            if 'signer-ocsp/s1' in url:
                return _imds_response(staple_b64)
            if 'active-keys' in url:
                return _imds_response('ssh-rsa AAAA test\nsig==\n')
            return _imds_response('')

        mock_urlopen.side_effect = urlopen_router

        with patch.object(sys, 'argv', ['ec2_instance_connect_rhel.eic_curl.py', 'testuser']):
            with self.assertRaises(SystemExit) as ctx:
                eic_curl.main()

        self.assertEqual(ctx.exception.code, 0)
        mock_parse_run.assert_called_once()
        self.assertEqual(
            mock_parse_run.call_args.kwargs['ca_path'], eic_curl.CA_BUNDLE)
        self.assertTrue(
            mock_parse_run.call_args.kwargs['signer_path'].endswith(
                'signer-cert.pem'))

    @patch('syslog.syslog')
    @patch('pwd.getpwnam', side_effect=KeyError('no such user'))
    def test_nonexistent_user_exits_0(self, _mock_pwd, _mock_syslog):
        with patch.object(sys, 'argv', ['ec2_instance_connect_rhel.eic_curl.py', 'nosuchuser']):
            with self.assertRaises(SystemExit) as ctx:
                eic_curl.main()
        self.assertEqual(ctx.exception.code, 0)

    @patch('syslog.syslog')
    def test_no_username_exits_1(self, _mock_syslog):
        with patch.object(sys, 'argv', ['ec2_instance_connect_rhel.eic_curl.py']):
            with self.assertRaises(SystemExit) as ctx:
                eic_curl.main()
        self.assertEqual(ctx.exception.code, 1)


if __name__ == '__main__':
    unittest.main()

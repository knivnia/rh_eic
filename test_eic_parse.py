#!/usr/bin/env python3

import base64
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from eic_parse import (
    parse_arguments,
    split_cert_chain,
    build_ca_bundles_dir,
    build_ca_trust_chain,
    extract_cn,
    extract_from_bundle,
    get_cert_hash,
    get_cert_fingerprint,
    get_cert_pubkey,
    is_cert_trusted,
    verify_ocsp,
    verify_ocsp_chain,
    verify_trust_chain,
    get_ssh_key_fingerprint,
    verify_key_signature,
    parse_key_entries,
    process_keys,
    main,
)


class TestParseArguments(unittest.TestCase):
    """Test the parse_arguments function."""

    def test_all_required_args(self):
        """Test parsing with all required arguments provided."""
        test_args = [
            'eic_parse.py',
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

            self.assertEqual(args.expected_key, 'SHA256:abcdef1234567890')

    def test_missing_required_arg(self):
        """Test that missing required argument causes exit."""
        test_args = [
            'eic_parse.py',
            '-p', '/tmp/keys'
            # Missing other required args
        ]

        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit):
                parse_arguments()

class TestSplitCertChain(unittest.TestCase):
    """Test the split_cert_chain function."""

    def setUp(self):
        """Create a temporary directory for tests."""
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_single_certificate(self):
        """Test splitting a single certificate."""
        signer = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU/ZOMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RDQTAeFw0yMTAxMDEwMDAwMDBaFw0yMjAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1234567890abcdef
-----END CERTIFICATE-----"""

        certs = split_cert_chain(signer, self.tmpdir)

        self.assertEqual(len(certs), 1)
        self.assertTrue(os.path.exists(certs[0]))
        self.assertEqual(os.path.basename(certs[0]), "cert0.pem")

        # Verify content
        with open(certs[0]) as f:
            content = f.read()
        self.assertIn("-----BEGIN CERTIFICATE-----", content)
        self.assertIn("-----END CERTIFICATE-----", content)

    def test_multiple_certificates(self):
        """Test splitting a chain with 3 certificates."""
        signer = """-----BEGIN CERTIFICATE-----
CERT1LINE1
CERT1LINE2
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
CERT2LINE1
CERT2LINE2
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
CERT3LINE1
CERT3LINE2
-----END CERTIFICATE-----"""

        certs = split_cert_chain(signer, self.tmpdir)

        self.assertEqual(len(certs), 3)
        self.assertEqual(os.path.basename(certs[0]), "cert0.pem")
        self.assertEqual(os.path.basename(certs[1]), "cert1.pem")
        self.assertEqual(os.path.basename(certs[2]), "cert2.pem")

        # Verify first cert content
        with open(certs[0]) as f:
            cert0_content = f.read()
        self.assertIn("CERT1LINE1", cert0_content)
        self.assertNotIn("CERT2LINE1", cert0_content)

        # Verify second cert content
        with open(certs[1]) as f:
            cert1_content = f.read()
        self.assertIn("CERT2LINE1", cert1_content)
        self.assertNotIn("CERT1LINE1", cert1_content)

    def test_empty_chain(self):
        """Test splitting an empty certificate chain."""
        signer = ""
        certs = split_cert_chain(signer, self.tmpdir)
        self.assertEqual(len(certs), 0)

    def test_whitespace_handling(self):
        """Test that whitespace around END CERTIFICATE is handled."""
        signer = """-----BEGIN CERTIFICATE-----
LINE1
  -----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
LINE2
-----END CERTIFICATE-----"""

        certs = split_cert_chain(signer, self.tmpdir)

        self.assertEqual(len(certs), 2)
        # Both certs should be created despite whitespace
        self.assertTrue(os.path.exists(certs[0]))
        self.assertTrue(os.path.exists(certs[1]))


class TestExtractCN(unittest.TestCase):
    """Test the extract_cn function."""

    def setUp(self):
        """Create a temporary directory and certificate file."""
        self.tmpdir = tempfile.mkdtemp()
        self.cert_path = Path(self.tmpdir) / "test.pem"

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_extract_cn_success(self):
        """Test extracting CN from a certificate."""
        import shutil as sh
        import subprocess

        # Skip test if openssl is not available
        if not sh.which("openssl"):
            self.skipTest("openssl not available")

        # Generate a real self-signed certificate for testing
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(Path(self.tmpdir) / "key.pem"),
            "-out", str(self.cert_path),
            "-days", "1",
            "-subj", "/CN=testCA"
        ], capture_output=True, check=True)

        cn = extract_cn("openssl", self.cert_path)
        self.assertEqual(cn, "testCA")


class TestExtractFromBundle(unittest.TestCase):
    """Test the extract_from_bundle function."""

    def setUp(self):
        """Create a temporary directory and bundle file."""
        self.tmpdir = tempfile.mkdtemp()
        self.bundle_path = Path(self.tmpdir) / "ca-bundle.pem"
        self.output_dir = Path(self.tmpdir) / "output"
        self.output_dir.mkdir()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_extract_from_bundle(self):
        """Test extracting a certificate from a bundle."""
        bundle_content = """# Test CA
-----BEGIN CERTIFICATE-----
TESTCACERT1
TESTCACERT2
-----END CERTIFICATE-----
# Another CA
-----BEGIN CERTIFICATE-----
ANOTHERCERT1
ANOTHERCERT2
-----END CERTIFICATE-----"""
        self.bundle_path.write_text(bundle_content)

        extract_from_bundle(self.bundle_path, "Test CA", self.output_dir)

        output_file = self.output_dir / "Test CA"
        self.assertTrue(output_file.exists())
        content = output_file.read_text()
        self.assertIn("TESTCACERT1", content)
        self.assertIn("-----END CERTIFICATE-----", content)

    def test_extract_from_bundle_not_found(self):
        """Test extracting a non-existent subject from bundle."""
        bundle_content = """# Test CA
-----BEGIN CERTIFICATE-----
TESTCACERT1
-----END CERTIFICATE-----"""
        self.bundle_path.write_text(bundle_content)

        extract_from_bundle(self.bundle_path, "Nonexistent CA", self.output_dir)

        output_file = self.output_dir / "Nonexistent CA"
        self.assertFalse(output_file.exists())


class TestBuildCABundlesDir(unittest.TestCase):
    """Test the build_ca_bundles_dir function."""

    def setUp(self):
        """Create a temporary directory structure."""
        self.tmpdir = tempfile.mkdtemp()
        self.ca_dir = os.path.join(self.tmpdir, "ca-certs")
        os.makedirs(self.ca_dir)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_empty_cert_files(self):
        """Test with empty cert_files list."""
        result = build_ca_bundles_dir(
            "openssl", [], self.ca_dir, self.tmpdir)
        self.assertTrue(os.path.exists(result))
        self.assertTrue(os.path.isdir(result))

    def test_with_cert_files(self):
        """Test with certificate files."""
        # Create test certificate files
        cert0 = os.path.join(self.tmpdir, "cert0.pem")
        cert1 = os.path.join(self.tmpdir, "cert1.pem")
        with open(cert0, "w") as f:
            f.write("CERT0")
        with open(cert1, "w") as f:
            f.write("CERT1")
        cert_files = [cert0, cert1]

        result = build_ca_bundles_dir(
            "openssl", cert_files, self.ca_dir, self.tmpdir)
        self.assertTrue(os.path.exists(result))
        self.assertTrue(os.path.isdir(result))


class TestBuildCATrustChain(unittest.TestCase):
    """Test the build_ca_trust_chain function."""

    def setUp(self):
        """Create a temporary directory and test files."""
        self.tmpdir = tempfile.mkdtemp()
        self.ca_bundles_dir = os.path.join(self.tmpdir, "ca-bundles")
        os.makedirs(self.ca_bundles_dir)

        # Create test certificate files
        self.cert0 = os.path.join(self.tmpdir, "cert0.pem")
        self.cert1 = os.path.join(self.tmpdir, "cert1.pem")
        with open(self.cert0, "w") as f:
            f.write("CERT0CONTENT\n")
        with open(self.cert1, "w") as f:
            f.write("CERT1CONTENT\n")
        self.cert_files = [self.cert0, self.cert1]

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_build_ca_trust_chain(self):
        """Test building CA trust chain."""
        # Create a CA bundle file
        ca_bundle = os.path.join(self.ca_bundles_dir, "test_ca")
        with open(ca_bundle, "w") as f:
            f.write("CABUNDLECONTENT\n")

        result = build_ca_trust_chain(
            self.cert_files,
            self.tmpdir,
            self.ca_bundles_dir
        )

        self.assertTrue(os.path.exists(result))
        self.assertEqual(os.path.basename(result), "ca-trust.pem")

        # Verify content includes cert1 and ca bundle
        with open(result) as f:
            content = f.read()
        self.assertIn("CERT1CONTENT", content)
        self.assertIn("CABUNDLECONTENT", content)

    def test_empty_ca_bundles_dir(self):
        """Test with empty ca_bundles_dir."""
        result = build_ca_trust_chain(
            self.cert_files,
            self.tmpdir,
            self.ca_bundles_dir
        )

        self.assertTrue(os.path.exists(result))
        with open(result) as f:
            content = f.read()
        self.assertIn("CERT1CONTENT", content)


class TestGetCertHash(unittest.TestCase):
    """Test the get_cert_hash function."""

    def setUp(self):
        """Create a temporary directory and certificate file."""
        self.tmpdir = tempfile.mkdtemp()
        self.cert_path = Path(self.tmpdir) / "test.pem"

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_get_cert_hash(self):
        """Test getting certificate hash."""
        import shutil as sh
        import subprocess

        if not sh.which("openssl"):
            self.skipTest("openssl not available")

        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(Path(self.tmpdir) / "key.pem"),
            "-out", str(self.cert_path),
            "-days", "1",
            "-subj", "/CN=testCA"
        ], capture_output=True, check=True)

        hash_result = get_cert_hash("openssl", self.cert_path)
        self.assertIsNotNone(hash_result)
        self.assertTrue(len(hash_result) > 0)


class TestGetCertFingerprint(unittest.TestCase):
    """Test the get_cert_fingerprint function."""

    def setUp(self):
        """Create a temporary directory and certificate file."""
        self.tmpdir = tempfile.mkdtemp()
        self.cert_path = Path(self.tmpdir) / "test.pem"

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_get_cert_fingerprint(self):
        """Test getting certificate fingerprint."""
        import shutil as sh
        import subprocess

        if not sh.which("openssl"):
            self.skipTest("openssl not available")

        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(Path(self.tmpdir) / "key.pem"),
            "-out", str(self.cert_path),
            "-days", "1",
            "-subj", "/CN=testCA"
        ], capture_output=True, check=True)

        fp = get_cert_fingerprint("openssl", self.cert_path)
        self.assertIsNotNone(fp)
        # SHA1 fingerprint without colons should be 40 hex chars
        self.assertEqual(len(fp), 40)


class TestGetCertPubkey(unittest.TestCase):
    """Test the get_cert_pubkey function."""

    def setUp(self):
        """Create a temporary directory and certificate file."""
        self.tmpdir = tempfile.mkdtemp()
        self.cert_path = Path(self.tmpdir) / "test.pem"

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_get_cert_pubkey(self):
        """Test getting certificate public key."""
        import shutil as sh
        import subprocess

        if not sh.which("openssl"):
            self.skipTest("openssl not available")

        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(Path(self.tmpdir) / "key.pem"),
            "-out", str(self.cert_path),
            "-days", "1",
            "-subj", "/CN=testCA"
        ], capture_output=True, check=True)

        pubkey = get_cert_pubkey("openssl", self.cert_path)
        self.assertIsNotNone(pubkey)
        self.assertIn("BEGIN PUBLIC KEY", pubkey)


class TestIsCertTrusted(unittest.TestCase):
    """Test the is_cert_trusted function."""

    def setUp(self):
        """Create a temporary directory and certificate files."""
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_same_cert_is_trusted(self):
        """Test that same certificate is trusted."""
        import shutil as sh
        import subprocess

        if not sh.which("openssl"):
            self.skipTest("openssl not available")

        cert_path = Path(self.tmpdir) / "test.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(Path(self.tmpdir) / "key.pem"),
            "-out", str(cert_path),
            "-days", "1",
            "-subj", "/CN=testCA"
        ], capture_output=True, check=True)

        # Same certificate should be trusted
        self.assertTrue(is_cert_trusted("openssl", cert_path, cert_path))

    def test_different_cert_not_trusted(self):
        """Test that different certificate is not trusted."""
        import shutil as sh
        import subprocess

        if not sh.which("openssl"):
            self.skipTest("openssl not available")

        cert1_path = Path(self.tmpdir) / "cert1.pem"
        cert2_path = Path(self.tmpdir) / "cert2.pem"

        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(Path(self.tmpdir) / "key1.pem"),
            "-out", str(cert1_path),
            "-days", "1",
            "-subj", "/CN=testCA1"
        ], capture_output=True, check=True)

        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(Path(self.tmpdir) / "key2.pem"),
            "-out", str(cert2_path),
            "-days", "1",
            "-subj", "/CN=testCA2"
        ], capture_output=True, check=True)

        # Different certificates should not be trusted
        self.assertFalse(is_cert_trusted("openssl", cert1_path, cert2_path))


class TestVerifyTrustChain(unittest.TestCase):
    """Test the verify_trust_chain function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_valid_chain(self, mock_run, _mock_syslog):
        """verify_trust_chain should pass when openssl verify succeeds."""
        cert_file = Path(self.tmpdir) / "cert.pem"
        ca_trust = Path(self.tmpdir) / "ca-trust.pem"
        cert_file.write_text("CERT")
        ca_trust.write_text("CA")

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=f"{cert_file}: OK"
        )
        # Should not raise
        verify_trust_chain("openssl", cert_file, "/etc/ssl/certs", ca_trust)
        mock_run.assert_called_once()

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_invalid_chain_exits_1(self, mock_run, _mock_syslog):
        """verify_trust_chain should exit 1 on verification failure."""
        cert_file = Path(self.tmpdir) / "cert.pem"
        ca_trust = Path(self.tmpdir) / "ca-trust.pem"
        cert_file.write_text("CERT")
        ca_trust.write_text("CA")

        mock_run.return_value = MagicMock(
            returncode=2,
            stdout="error 20 at 0 depth"
        )
        with self.assertRaises(SystemExit) as ctx:
            verify_trust_chain("openssl", cert_file, "/etc/ssl/certs",
                               ca_trust)
        self.assertEqual(ctx.exception.code, 1)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_wrong_stdout_exits_1(self, mock_run, _mock_syslog):
        """Exit 1 even if returncode is 0 but stdout is unexpected."""
        cert_file = Path(self.tmpdir) / "cert.pem"
        ca_trust = Path(self.tmpdir) / "ca-trust.pem"
        cert_file.write_text("CERT")
        ca_trust.write_text("CA")

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="some garbage"
        )
        with self.assertRaises(SystemExit) as ctx:
            verify_trust_chain("openssl", cert_file, "/etc/ssl/certs",
                               ca_trust)
        self.assertEqual(ctx.exception.code, 1)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_uses_capath_for_directory(self, mock_run, _mock_syslog):
        """When ca_path is a directory, -CApath should be used."""
        cert_file = Path(self.tmpdir) / "cert.pem"
        ca_trust = Path(self.tmpdir) / "ca-trust.pem"
        cert_file.write_text("CERT")
        ca_trust.write_text("CA")

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=f"{cert_file}: OK"
        )
        # self.tmpdir is a real directory
        verify_trust_chain("openssl", cert_file, self.tmpdir, ca_trust)
        cmd = mock_run.call_args[0][0]
        self.assertIn("-CApath", cmd)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_no_capath_for_file(self, mock_run, _mock_syslog):
        """When ca_path is a file, only -CAfile should be used."""
        cert_file = Path(self.tmpdir) / "cert.pem"
        ca_trust = Path(self.tmpdir) / "ca-trust.pem"
        ca_bundle = Path(self.tmpdir) / "ca-bundle.crt"
        cert_file.write_text("CERT")
        ca_trust.write_text("CA")
        ca_bundle.write_text("BUNDLE")

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=f"{cert_file}: OK"
        )
        verify_trust_chain("openssl", cert_file, str(ca_bundle), ca_trust)
        cmd = mock_run.call_args[0][0]
        self.assertNotIn("-CApath", cmd)
        self.assertIn("-CAfile", cmd)


class TestVerifyOcsp(unittest.TestCase):
    """Test the verify_ocsp function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_good_response(self, mock_run, _mock_syslog):
        """OCSP check passes when openssl returns 'good'."""
        cert = Path(self.tmpdir) / "cert.pem"
        issuer = Path(self.tmpdir) / "issuer.pem"
        ocsp_dir = Path(self.tmpdir) / "ocsp"
        ocsp_dir.mkdir()
        cert.write_text("CERT")
        issuer.write_text("ISSUER")

        # get_cert_fingerprint and extract_cn are called internally --
        # mock subprocess.run to handle both openssl calls
        call_count = [0]
        def run_side_effect(cmd, **kwargs):
            call_count[0] += 1
            if 'x509' in cmd and '-subject' in cmd:
                return MagicMock(returncode=0, stdout="subject=CN = testCN")
            if 'x509' in cmd and '-fingerprint' in cmd:
                fp = "AABB" * 10  # 40 hex chars
                return MagicMock(
                    returncode=0,
                    stdout=f"SHA1 Fingerprint={fp}")
            if 'ocsp' in cmd:
                return MagicMock(
                    returncode=0,
                    stdout=f"{cert}: good")
            return MagicMock(returncode=0, stdout="")

        mock_run.side_effect = run_side_effect

        # Create the OCSP response file named by fingerprint
        fp = "AABB" * 10
        (ocsp_dir / fp).write_bytes(b"OCSP_RESPONSE")

        verify_ocsp("openssl", cert, issuer, ocsp_dir)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_revoked_exits_1(self, mock_run, _mock_syslog):
        """OCSP check should exit 1 when cert is revoked."""
        cert = Path(self.tmpdir) / "cert.pem"
        issuer = Path(self.tmpdir) / "issuer.pem"
        ocsp_dir = Path(self.tmpdir) / "ocsp"
        ocsp_dir.mkdir()
        cert.write_text("CERT")
        issuer.write_text("ISSUER")

        def run_side_effect(cmd, **kwargs):
            if 'x509' in cmd and '-subject' in cmd:
                return MagicMock(returncode=0, stdout="subject=CN = testCN")
            if 'x509' in cmd and '-fingerprint' in cmd:
                fp = "AABB" * 10
                return MagicMock(
                    returncode=0,
                    stdout=f"SHA1 Fingerprint={fp}")
            if 'ocsp' in cmd:
                return MagicMock(
                    returncode=1,
                    stdout=f"{cert}: revoked")
            return MagicMock(returncode=0, stdout="")

        mock_run.side_effect = run_side_effect
        fp = "AABB" * 10
        (ocsp_dir / fp).write_bytes(b"OCSP_RESPONSE")

        with self.assertRaises(SystemExit) as ctx:
            verify_ocsp("openssl", cert, issuer, ocsp_dir)
        self.assertEqual(ctx.exception.code, 1)


class TestVerifyOcspChain(unittest.TestCase):
    """Test the verify_ocsp_chain function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @patch('syslog.syslog')
    @patch('eic_parse.verify_ocsp')
    @patch('eic_parse.is_cert_trusted', return_value=False)
    @patch('eic_parse.extract_cn', return_value="SomeCN")
    def test_iterates_chain(self, _mock_cn, _mock_trusted,
                            mock_verify, _mock_syslog):
        """Should call verify_ocsp for each cert pair in the chain."""
        cert0 = Path(self.tmpdir) / "cert0.pem"
        cert1 = Path(self.tmpdir) / "cert1.pem"
        cert2 = Path(self.tmpdir) / "cert2.pem"
        for c in (cert0, cert1, cert2):
            c.write_text("CERT")

        ca_bundles = Path(self.tmpdir) / "bundles"
        ca_bundles.mkdir()
        ocsp_dir = Path(self.tmpdir) / "ocsp"
        ocsp_dir.mkdir()

        verify_ocsp_chain("openssl", [cert0, cert1, cert2],
                          ca_bundles, ocsp_dir)
        # Should verify cert0 against cert1, then cert1 against cert2
        self.assertEqual(mock_verify.call_count, 2)

    @patch('syslog.syslog')
    @patch('eic_parse.verify_ocsp')
    @patch('eic_parse.is_cert_trusted', return_value=True)
    @patch('eic_parse.extract_cn', return_value="TrustedCN")
    def test_stops_at_trusted_cert(self, _mock_cn, _mock_trusted,
                                   mock_verify, _mock_syslog):
        """Should stop verifying when a trusted cert is found."""
        cert0 = Path(self.tmpdir) / "cert0.pem"
        cert1 = Path(self.tmpdir) / "cert1.pem"
        cert2 = Path(self.tmpdir) / "cert2.pem"
        for c in (cert0, cert1, cert2):
            c.write_text("CERT")

        ca_bundles = Path(self.tmpdir) / "bundles"
        ca_bundles.mkdir()
        # Create a matching trusted cert file
        (ca_bundles / "TrustedCN").write_text("TRUSTED")
        ocsp_dir = Path(self.tmpdir) / "ocsp"
        ocsp_dir.mkdir()

        verify_ocsp_chain("openssl", [cert0, cert1, cert2],
                          ca_bundles, ocsp_dir)
        # Should stop at cert0 because it's trusted -- no OCSP calls
        mock_verify.assert_not_called()


class TestVerifyKeySignature(unittest.TestCase):
    """Test the verify_key_signature function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_valid_signature(self, mock_run, _mock_syslog):
        """Returns True when openssl dgst verifies successfully."""
        pubkey_file = Path(self.tmpdir) / "pubkey.pem"
        pubkey_file.write_text("PUBKEY")

        sig_b64 = base64.b64encode(b"SIGNATURE").decode()
        mock_run.return_value = MagicMock(returncode=0)

        result = verify_key_signature(
            "openssl", "signed data here", sig_b64,
            pubkey_file, self.tmpdir)
        self.assertTrue(result)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_invalid_signature(self, mock_run, _mock_syslog):
        """Returns False when openssl dgst fails."""
        pubkey_file = Path(self.tmpdir) / "pubkey.pem"
        pubkey_file.write_text("PUBKEY")

        sig_b64 = base64.b64encode(b"BADSIG").decode()
        mock_run.return_value = MagicMock(returncode=1)

        result = verify_key_signature(
            "openssl", "signed data", sig_b64,
            pubkey_file, self.tmpdir)
        self.assertFalse(result)

    @patch('syslog.syslog')
    def test_invalid_base64_returns_false(self, _mock_syslog):
        """Returns False when base64 decoding fails."""
        pubkey_file = Path(self.tmpdir) / "pubkey.pem"
        pubkey_file.write_text("PUBKEY")

        result = verify_key_signature(
            "openssl", "data", "NOT-VALID-BASE64!!!",
            pubkey_file, self.tmpdir)
        self.assertFalse(result)

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_cleans_up_temp_files(self, mock_run, _mock_syslog):
        """Temp files should be cleaned up after verification."""
        pubkey_file = Path(self.tmpdir) / "pubkey.pem"
        pubkey_file.write_text("PUBKEY")

        sig_b64 = base64.b64encode(b"SIG").decode()
        mock_run.return_value = MagicMock(returncode=0)

        verify_key_signature(
            "openssl", "data", sig_b64,
            pubkey_file, self.tmpdir)

        signed_data_file = os.path.join(self.tmpdir, "signed_data")
        sig_file = os.path.join(self.tmpdir, "decoded_sig")
        self.assertFalse(os.path.exists(signed_data_file))
        self.assertFalse(os.path.exists(sig_file))


class TestGetSshKeyFingerprint(unittest.TestCase):
    """Test the get_ssh_key_fingerprint function."""

    def setUp(self):
        """Create a temporary directory."""
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.tmpdir)

    def test_valid_ssh_key(self):
        """Test getting fingerprint from a valid SSH key."""
        if not shutil.which("ssh-keygen"):
            self.skipTest("ssh-keygen not available")

        key_file = Path(self.tmpdir) / "test_key"
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "2048",
             "-f", str(key_file), "-N", ""],
            capture_output=True,
            check=True
        )

        with open(f"{key_file}.pub", "r") as f:
            public_key = f.read().strip()

        fingerprint = get_ssh_key_fingerprint(public_key, self.tmpdir)

        self.assertIsNotNone(fingerprint)
        self.assertTrue(len(fingerprint) > 0)
        self.assertTrue(
            ":" in fingerprint or fingerprint.startswith("SHA256:"))

    def test_invalid_key(self):
        """Test that invalid key returns None."""
        result = get_ssh_key_fingerprint("invalid key data", self.tmpdir)
        self.assertIsNone(result)


class TestParseKeyEntries(unittest.TestCase):
    """Test the parse_key_entries function."""

    def test_parse_single_entry(self):
        """Test parsing a single valid key entry."""
        lines = [
            "#Timestamp=1234567890\n",
            "#Instance=i-1234567890abcdef0\n",
            "#Caller=arn:aws:iam::123456789012:user/test\n",
            "#Request=req-12345\n",
            "ssh-rsa AAAAB3NzaC1yc2EA test@example.com\n",
            "base64signature==\n",
            "\n"
        ]

        entries = list(parse_key_entries(lines))

        self.assertEqual(len(entries), 1)
        self.assertEqual(
            entries[0]["key"],
            "ssh-rsa AAAAB3NzaC1yc2EA test@example.com")
        self.assertEqual(entries[0]["signature"], "base64signature==")
        self.assertEqual(
            entries[0]["metadata"]["timestamp"], "1234567890")
        self.assertEqual(
            entries[0]["metadata"]["instance_id"],
            "i-1234567890abcdef0")
        self.assertEqual(
            entries[0]["metadata"]["caller"],
            "arn:aws:iam::123456789012:user/test")
        self.assertEqual(
            entries[0]["metadata"]["request"], "req-12345")

    def test_parse_multiple_entries(self):
        """Test parsing multiple key entries."""
        lines = [
            "#Timestamp=1111111111\n",
            "#Instance=i-aaaaaaaaaaaaa\n",
            "ssh-rsa AAAA1111 test1\n",
            "sig1==\n",
            "\n",
            "#Timestamp=2222222222\n",
            "#Instance=i-bbbbbbbbbbbbb\n",
            "ssh-rsa AAAA2222 test2\n",
            "sig2==\n",
        ]

        entries = list(parse_key_entries(lines))

        self.assertEqual(len(entries), 2)
        self.assertEqual(
            entries[0]["metadata"]["timestamp"], "1111111111")
        self.assertEqual(
            entries[1]["metadata"]["timestamp"], "2222222222")

    def test_skip_invalid_entry(self):
        """Test that invalid entries are skipped."""
        lines = [
            "#Timestamp=1234567890\n",
            "#Instance=i-invalid\n",
            "not-an-ssh-key\n",
            "signature\n",
            "\n",
            "#Timestamp=9876543210\n",
            "#Instance=i-valid\n",
            "ssh-rsa AAAVALID test\n",
            "validsig==\n",
        ]

        entries = list(parse_key_entries(lines))

        self.assertEqual(len(entries), 1)
        self.assertEqual(
            entries[0]["metadata"]["timestamp"], "9876543210")

    def test_empty_input(self):
        """Test parsing empty input."""
        entries = list(parse_key_entries([]))
        self.assertEqual(len(entries), 0)

    def test_whitespace_only_lines(self):
        """Test that whitespace-only lines are skipped."""
        lines = ["\n", "  \n", "\n"]
        entries = list(parse_key_entries(lines))
        self.assertEqual(len(entries), 0)


class TestProcessKeys(unittest.TestCase):
    """Test the process_keys function with mocked dependencies."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.keys_file = Path(self.tmpdir) / "keys"
        self.pubkey_file = Path(self.tmpdir) / "pubkey.pem"
        self.pubkey_file.write_text("PUBKEY")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @patch('syslog.syslog')
    @patch('eic_parse.verify_key_signature', return_value=True)
    @patch('eic_parse.get_ssh_key_fingerprint',
           return_value='SHA256:testfp')
    def test_valid_key_accepted(self, _mock_fp, _mock_sig, _mock_syslog):
        """A valid, non-expired key with matching instance ID is accepted."""
        future_ts = str(int(time.time()) + 3600)
        self.keys_file.write_text(
            f"#Timestamp={future_ts}\n"
            "#Instance=i-abc123\n"
            "ssh-rsa AAAA testkey\n"
            "sig==\n"
        )

        result = process_keys(
            str(self.keys_file), "i-abc123",
            int(time.time()), None,
            "openssl", self.pubkey_file, self.tmpdir)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], "ssh-rsa AAAA testkey")

    @patch('syslog.syslog')
    @patch('eic_parse.verify_key_signature', return_value=True)
    @patch('eic_parse.get_ssh_key_fingerprint',
           return_value='SHA256:testfp')
    def test_expired_key_rejected(self, _mock_fp, _mock_sig, _mock_syslog):
        """An expired key (timestamp in the past) is rejected."""
        past_ts = str(int(time.time()) - 3600)
        self.keys_file.write_text(
            f"#Timestamp={past_ts}\n"
            "#Instance=i-abc123\n"
            "ssh-rsa AAAA testkey\n"
            "sig==\n"
        )

        result = process_keys(
            str(self.keys_file), "i-abc123",
            int(time.time()), None,
            "openssl", self.pubkey_file, self.tmpdir)

        self.assertEqual(len(result), 0)

    @patch('syslog.syslog')
    @patch('eic_parse.verify_key_signature', return_value=True)
    @patch('eic_parse.get_ssh_key_fingerprint',
           return_value='SHA256:testfp')
    def test_wrong_instance_id_rejected(self, _mock_fp, _mock_sig,
                                        _mock_syslog):
        """A key with a non-matching instance ID is rejected."""
        future_ts = str(int(time.time()) + 3600)
        self.keys_file.write_text(
            f"#Timestamp={future_ts}\n"
            "#Instance=i-DIFFERENT\n"
            "ssh-rsa AAAA testkey\n"
            "sig==\n"
        )

        result = process_keys(
            str(self.keys_file), "i-abc123",
            int(time.time()), None,
            "openssl", self.pubkey_file, self.tmpdir)

        self.assertEqual(len(result), 0)

    @patch('syslog.syslog')
    @patch('eic_parse.verify_key_signature', return_value=False)
    @patch('eic_parse.get_ssh_key_fingerprint',
           return_value='SHA256:testfp')
    def test_bad_signature_rejected(self, _mock_fp, _mock_sig, _mock_syslog):
        """A key with an invalid signature is rejected."""
        future_ts = str(int(time.time()) + 3600)
        self.keys_file.write_text(
            f"#Timestamp={future_ts}\n"
            "#Instance=i-abc123\n"
            "ssh-rsa AAAA testkey\n"
            "sig==\n"
        )

        result = process_keys(
            str(self.keys_file), "i-abc123",
            int(time.time()), None,
            "openssl", self.pubkey_file, self.tmpdir)

        self.assertEqual(len(result), 0)

    @patch('syslog.syslog')
    @patch('eic_parse.verify_key_signature', return_value=True)
    @patch('eic_parse.get_ssh_key_fingerprint',
           return_value='SHA256:wrongfp')
    def test_fingerprint_mismatch_rejected(self, _mock_fp, _mock_sig,
                                           _mock_syslog):
        """When expected_key is set, mismatched fingerprint is rejected."""
        future_ts = str(int(time.time()) + 3600)
        self.keys_file.write_text(
            f"#Timestamp={future_ts}\n"
            "#Instance=i-abc123\n"
            "ssh-rsa AAAA testkey\n"
            "sig==\n"
        )

        result = process_keys(
            str(self.keys_file), "i-abc123",
            int(time.time()), "SHA256:expectedfp",
            "openssl", self.pubkey_file, self.tmpdir)

        self.assertEqual(len(result), 0)

    @patch('syslog.syslog')
    def test_missing_keys_file(self, _mock_syslog):
        """Returns empty list when keys file doesn't exist."""
        result = process_keys(
            "/nonexistent/path", "i-abc123",
            int(time.time()), None,
            "openssl", self.pubkey_file, self.tmpdir)

        self.assertEqual(len(result), 0)


class TestMain(unittest.TestCase):
    """Test the main() entry point."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @patch('syslog.syslog')
    @patch('eic_parse.process_keys', return_value=['ssh-rsa AAAA key'])
    @patch('eic_parse.get_cert_pubkey', return_value='BEGIN PUBLIC KEY')
    @patch('eic_parse.verify_ocsp_chain')
    @patch('eic_parse.verify_trust_chain')
    @patch('eic_parse.extract_cn', return_value='expected.signer.com')
    @patch('eic_parse.build_ca_trust_chain')
    @patch('eic_parse.build_ca_bundles_dir')
    @patch('eic_parse.split_cert_chain')
    @patch('shutil.rmtree')
    @patch('os.umask')
    @patch('time.time', return_value=1700000000.0)
    def test_main_with_valid_keys(self, _mock_time, _mock_umask,
                                  _mock_rmtree, mock_split,
                                  mock_bundles, mock_trust,
                                  mock_cn, mock_verify_trust,
                                  mock_verify_ocsp, mock_pubkey,
                                  mock_process, _mock_syslog):
        """main() should print valid keys and exit 0."""
        cert0 = Path(self.tmpdir) / "cert0.pem"
        cert1 = Path(self.tmpdir) / "cert1.pem"
        cert0.write_text("CERT0")
        cert1.write_text("CERT1")
        mock_split.return_value = [cert0, cert1]
        mock_bundles.return_value = Path(self.tmpdir) / "bundles"
        mock_trust.return_value = Path(self.tmpdir) / "ca-trust.pem"

        test_args = [
            'eic_parse.py',
            '-p', '/tmp/keys',
            '-o', '/usr/bin/openssl',
            '-d', self.tmpdir,
            '-s', 'CERT_CHAIN',
            '-i', 'i-abc123',
            '-c', 'expected.signer.com',
            '-a', '/etc/ssl/certs',
            '-v', '/tmp/ocsp',
        ]

        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)

    @patch('syslog.syslog')
    @patch('eic_parse.process_keys', return_value=[])
    @patch('eic_parse.get_cert_pubkey', return_value='BEGIN PUBLIC KEY')
    @patch('eic_parse.verify_ocsp_chain')
    @patch('eic_parse.verify_trust_chain')
    @patch('eic_parse.extract_cn', return_value='expected.signer.com')
    @patch('eic_parse.build_ca_trust_chain')
    @patch('eic_parse.build_ca_bundles_dir')
    @patch('eic_parse.split_cert_chain')
    @patch('shutil.rmtree')
    @patch('os.umask')
    @patch('time.time', return_value=1700000000.0)
    def test_main_no_valid_keys_exits_255(self, _mock_time, _mock_umask,
                                          _mock_rmtree, mock_split,
                                          mock_bundles, mock_trust,
                                          mock_cn, mock_verify_trust,
                                          mock_verify_ocsp, mock_pubkey,
                                          mock_process, _mock_syslog):
        """main() should exit 255 when no valid keys are found."""
        cert0 = Path(self.tmpdir) / "cert0.pem"
        cert1 = Path(self.tmpdir) / "cert1.pem"
        cert0.write_text("CERT0")
        cert1.write_text("CERT1")
        mock_split.return_value = [cert0, cert1]
        mock_bundles.return_value = Path(self.tmpdir) / "bundles"
        mock_trust.return_value = Path(self.tmpdir) / "ca-trust.pem"

        test_args = [
            'eic_parse.py',
            '-p', '/tmp/keys',
            '-o', '/usr/bin/openssl',
            '-d', self.tmpdir,
            '-s', 'CERT_CHAIN',
            '-i', 'i-abc123',
            '-c', 'expected.signer.com',
            '-a', '/etc/ssl/certs',
            '-v', '/tmp/ocsp',
        ]

        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 255)

    @patch('syslog.syslog')
    @patch('eic_parse.extract_cn', return_value='wrong.signer.com')
    @patch('eic_parse.build_ca_trust_chain')
    @patch('eic_parse.build_ca_bundles_dir')
    @patch('eic_parse.split_cert_chain')
    @patch('os.umask')
    def test_main_cn_mismatch_exits_1(self, _mock_umask, mock_split,
                                      mock_bundles, mock_trust,
                                      mock_cn, _mock_syslog):
        """main() should exit 1 when signer CN doesn't match."""
        cert0 = Path(self.tmpdir) / "cert0.pem"
        cert1 = Path(self.tmpdir) / "cert1.pem"
        cert0.write_text("CERT0")
        cert1.write_text("CERT1")
        mock_split.return_value = [cert0, cert1]
        mock_bundles.return_value = Path(self.tmpdir) / "bundles"
        mock_trust.return_value = Path(self.tmpdir) / "ca-trust.pem"

        test_args = [
            'eic_parse.py',
            '-p', '/tmp/keys',
            '-o', '/usr/bin/openssl',
            '-d', self.tmpdir,
            '-s', 'CERT_CHAIN',
            '-i', 'i-abc123',
            '-c', 'expected.signer.com',
            '-a', '/etc/ssl/certs',
            '-v', '/tmp/ocsp',
        ]

        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 1)


if __name__ == '__main__':
    unittest.main()

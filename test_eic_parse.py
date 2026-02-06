#!/usr/bin/env python3

"""
Unit tests for eic_parse.py
Tests argument parsing and other functions as they are implemented.
"""

import unittest
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
from eic_parse import (
    str_to_bool,
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
    process_keys
)
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


class TestSplitCertChain(unittest.TestCase):
    """Test the split_cert_chain function."""

    def setUp(self):
        """Create a temporary directory for tests."""
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
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
        self.assertTrue(certs[0].exists())
        self.assertEqual(certs[0].name, "cert0.pem")

        # Verify content
        content = certs[0].read_text()
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
        self.assertEqual(certs[0].name, "cert0.pem")
        self.assertEqual(certs[1].name, "cert1.pem")
        self.assertEqual(certs[2].name, "cert2.pem")

        # Verify first cert content
        cert0_content = certs[0].read_text()
        self.assertIn("CERT1LINE1", cert0_content)
        self.assertNotIn("CERT2LINE1", cert0_content)

        # Verify second cert content
        cert1_content = certs[1].read_text()
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
        self.assertTrue(certs[0].exists())
        self.assertTrue(certs[1].exists())


class TestExtractCN(unittest.TestCase):
    """Test the extract_cn function."""

    def setUp(self):
        """Create a temporary directory and certificate file."""
        self.tmpdir = tempfile.mkdtemp()
        self.cert_path = Path(self.tmpdir) / "test.pem"

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
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
        import shutil
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
        self.ca_dir = Path(self.tmpdir) / "ca-certs"
        self.ca_dir.mkdir()

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_empty_cert_files(self):
        """Test with empty cert_files list."""
        result = build_ca_bundles_dir("openssl", [], str(self.ca_dir), self.tmpdir)
        self.assertTrue(result.exists())
        self.assertTrue(result.is_dir())

    def test_with_cert_files(self):
        """Test with certificate files."""
        # Create test certificate files
        cert0 = Path(self.tmpdir) / "cert0.pem"
        cert1 = Path(self.tmpdir) / "cert1.pem"
        cert0.write_text("CERT0")
        cert1.write_text("CERT1")
        cert_files = [cert0, cert1]

        result = build_ca_bundles_dir("openssl", cert_files, str(self.ca_dir), self.tmpdir)
        self.assertTrue(result.exists())
        self.assertTrue(result.is_dir())


class TestBuildCATrustChain(unittest.TestCase):
    """Test the build_ca_trust_chain function."""

    def setUp(self):
        """Create a temporary directory and test files."""
        self.tmpdir = tempfile.mkdtemp()
        self.ca_bundles_dir = Path(self.tmpdir) / "ca-bundles"
        self.ca_bundles_dir.mkdir()

        # Create test certificate files
        self.cert0 = Path(self.tmpdir) / "cert0.pem"
        self.cert1 = Path(self.tmpdir) / "cert1.pem"
        self.cert0.write_text("CERT0CONTENT\n")
        self.cert1.write_text("CERT1CONTENT\n")
        self.cert_files = [self.cert0, self.cert1]

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_build_ca_trust_chain(self):
        """Test building CA trust chain."""
        # Create a CA bundle file
        ca_bundle = self.ca_bundles_dir / "test_ca"
        ca_bundle.write_text("CABUNDLECONTENT\n")

        result = build_ca_trust_chain(
            "openssl",
            self.cert_files,
            "/etc/ssl/certs",
            self.tmpdir,
            self.ca_bundles_dir
        )

        self.assertTrue(result.exists())
        self.assertEqual(result.name, "ca-trust.pem")

        # Verify content includes cert1 and ca bundle
        content = result.read_text()
        self.assertIn("CERT1CONTENT", content)
        self.assertIn("CABUNDLECONTENT", content)

    def test_empty_ca_bundles_dir(self):
        """Test with empty ca_bundles_dir."""
        result = build_ca_trust_chain(
            "openssl",
            self.cert_files,
            "/etc/ssl/certs",
            self.tmpdir,
            self.ca_bundles_dir
        )

        self.assertTrue(result.exists())
        content = result.read_text()
        self.assertIn("CERT1CONTENT", content)


class TestGetCertHash(unittest.TestCase):
    """Test the get_cert_hash function."""

    def setUp(self):
        """Create a temporary directory and certificate file."""
        self.tmpdir = tempfile.mkdtemp()
        self.cert_path = Path(self.tmpdir) / "test.pem"

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
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
        import shutil
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
        import shutil
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
        import shutil
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

    def test_placeholder(self):
        """Placeholder test for verify_trust_chain."""
        # This function requires valid cert chains and CA setup
        # Skipping detailed test for now
        pass


class TestVerifyOcsp(unittest.TestCase):
    """Test the verify_ocsp function."""

    def test_placeholder(self):
        """Placeholder test for verify_ocsp."""
        # This function requires OCSP responses which are complex to mock
        # Skipping detailed test for now
        pass


class TestVerifyOcspChain(unittest.TestCase):
    """Test the verify_ocsp_chain function."""

    def test_placeholder(self):
        """Placeholder test for verify_ocsp_chain."""
        # This function requires OCSP responses which are complex to mock
        # Skipping detailed test for now
        pass


class TestGetSshKeyFingerprint(unittest.TestCase):
    """Test the get_ssh_key_fingerprint function."""

    def setUp(self):
        """Create a temporary directory."""
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_valid_ssh_key(self):
        """Test getting fingerprint from a valid SSH key."""
        import shutil as sh
        import subprocess

        if not sh.which("ssh-keygen"):
            self.skipTest("ssh-keygen not available")

        # Generate a test SSH key
        key_file = Path(self.tmpdir) / "test_key"
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", str(key_file), "-N", ""],
            capture_output=True,
            check=True
        )

        # Read the public key
        with open(f"{key_file}.pub", "r") as f:
            public_key = f.read().strip()

        # Get fingerprint
        fingerprint = get_ssh_key_fingerprint(public_key, self.tmpdir)

        self.assertIsNotNone(fingerprint)
        self.assertTrue(len(fingerprint) > 0)
        # SHA256 fingerprints start with specific format
        self.assertTrue(":" in fingerprint or fingerprint.startswith("SHA256:"))

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
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@example.com\n",
            "base64signature==\n",
            "\n"
        ]

        entries = list(parse_key_entries(lines))

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["key"], "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@example.com")
        self.assertEqual(entries[0]["signature"], "base64signature==")
        self.assertEqual(entries[0]["metadata"]["timestamp"], "1234567890")
        self.assertEqual(entries[0]["metadata"]["instance_id"], "i-1234567890abcdef0")
        self.assertEqual(entries[0]["metadata"]["caller"], "arn:aws:iam::123456789012:user/test")
        self.assertEqual(entries[0]["metadata"]["request"], "req-12345")

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
        self.assertEqual(entries[0]["metadata"]["timestamp"], "1111111111")
        self.assertEqual(entries[1]["metadata"]["timestamp"], "2222222222")

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

        # Should only get the valid entry
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["metadata"]["timestamp"], "9876543210")


class TestProcessKeys(unittest.TestCase):
    """Test the process_keys function."""

    def test_placeholder(self):
        """Placeholder test for process_keys."""
        # This is an integration test requiring valid certificates,
        # signatures, and key files - complex to set up
        # Skipping detailed test for now
        pass


if __name__ == '__main__':
    unittest.main()

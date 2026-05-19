#!/usr/bin/python3

from pathlib import Path

import argparse
import base64
import os
import re
import shutil
import subprocess
import sys
import syslog
import tempfile
import time


def log_info(message):
    syslog.syslog(syslog.LOG_AUTHPRIV | syslog.LOG_INFO, message)


def str_to_bool(word):
    if word.lower() == "true":
        return True
    elif word.lower() == "false":
        return False
    else:
        raise argparse.ArgumentTypeError(f"Boolean expected ('true' or 'false'), got {word}.")


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-x", dest="is_debug", required=True, type=str_to_bool)
    parser.add_argument("-p", dest="keys_path", required=True)
    parser.add_argument("-o", dest="openssl", required=True)
    parser.add_argument("-d", dest="tmpdir", required=True)
    parser.add_argument("-s", dest="signer", required=True)
    parser.add_argument("-i", dest="current_instance_id", required=True)
    parser.add_argument("-c", dest="expected_cn", required=True)
    parser.add_argument("-a", dest="ca_path", required=True)
    parser.add_argument("-v", dest="ocsp_dir_path", required=True)
    parser.add_argument("-f", dest="expected_key", default=None)

    return parser.parse_args()


def split_cert_chain(signer, tmpdir):
    certs = []
    cur_cert = []
    cert_count = 0

    for line in signer.splitlines():
        cur_cert.append(line)
        if line.strip() == "-----END CERTIFICATE-----":
            cert_path = Path(tmpdir) / f"cert{cert_count}.pem"
            cert_path.write_text("\n".join(cur_cert) + "\n")
            certs.append(cert_path)
            cur_cert = []
            cert_count += 1

    return certs


def build_ca_bundles_dir(openssl_cmd, cert_files, ca_path, tmpdir):
    ca_path_obj = Path(ca_path)
    if ca_path_obj.is_dir():
        ca_path_dir = ca_path_obj
    else:
        ca_path_dir = ca_path_obj.parent

    ca_bundles_dir = Path(tempfile.mkdtemp(prefix="eic-cert-", dir=tmpdir))

    if not cert_files:
        return ca_bundles_dir

    for i in range(1, len(cert_files)):
        cert_file = cert_files[i]
        subject = extract_cn(openssl_cmd, cert_file)
        if not subject:
            continue
        underscored = subject.replace(" ", "_")
        ca_cert = ca_path_dir / f"{underscored}.pem"
        if ca_cert.exists():
            shutil.copy(ca_cert, ca_bundles_dir / underscored)
        elif not ca_path_obj.is_dir():
            extract_from_bundle(ca_path, subject, ca_bundles_dir)

    return ca_bundles_dir


def extract_cn(openssl_cmd, cert_path):
    result = subprocess.run(
        [openssl_cmd, "x509", "-noout", "-subject", "-in", str(cert_path)],
        capture_output=True,
        text=True,
        check=False
    )
    match = re.search(r"CN\s*=\s*(.+?)(?:,|$)", result.stdout)
    if not match:
        return None
    return match.group(1).strip()


def extract_from_bundle(bundle_path, subject, output_dir):
    try:
        with open(bundle_path, "r") as file:
            content = file.read()

        lines = content.splitlines()
        cert_lines = []

        for i, line in enumerate(lines):
            if re.search(rf"#\s*{re.escape(subject)}\s*$", line):
                for line in lines[i+1:]:
                    if line.strip() and not line.startswith("#"):
                        cert_lines.append(line)
                    if "-----END CERTIFICATE-----" in line:
                        break
                break

        if cert_lines and "-----END CERTIFICATE-----" in "\n".join(cert_lines):
            output_file = output_dir / subject
            output_file.write_text("\n".join(cert_lines) + "\n")

    except (FileNotFoundError, PermissionError, IOError) as e:
        log_info(f"Could not extract {subject} from bundle: {e}.")


def build_ca_trust_chain(openssl_cmd, cert_files, ca_path, tmpdir, ca_bundles_dir):
    ca_trust_file = Path(tmpdir) / "ca-trust.pem"
    shutil.copy(cert_files[1], ca_trust_file)

    for cert_file in ca_bundles_dir.iterdir():
        if cert_file.is_file():
            with open(ca_trust_file, "a") as file:
                file.write(cert_file.read_text())

    ca_trust_file.chmod(0o400)
    return ca_trust_file


def verify_trust_chain(openssl_cmd, cert_file, ca_path, ca_trust_file):
    ca_path_obj = Path(ca_path)
    if ca_path_obj.is_dir():
        cmd = [
            openssl_cmd, "verify", "-x509_strict",
            "-CApath", str(ca_path),
            "-CAfile", str(ca_trust_file),
            str(cert_file)
        ]
    else:
        cmd = [
            openssl_cmd, "verify", "-x509_strict",
            "-CAfile", str(ca_trust_file),
            str(cert_file)
        ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    expected_output = f"{cert_file}: OK"

    if result.returncode != 0 or result.stdout.strip() != expected_output:
        log_info("EC2 Instance Connect could not verify the signer trust chain. No keys have been trusted.")
        sys.exit(1)


def get_cert_hash(openssl_cmd, cert):
    result = subprocess.run(
        [openssl_cmd, "x509", "-hash", "-noout", "-in", str(cert)],
        capture_output=True,
        text=True,
        check=False
    )
    return result.stdout.strip()


def get_cert_fingerprint(openssl_cmd, cert):
    result = subprocess.run(
        [openssl_cmd, "x509", "-fingerprint", "-sha1", "-noout", "-in", str(cert)],
        capture_output=True,
        text=True,
        check=False
    )
    match = re.search(r"SHA1\s+Fingerprint\s*=\s*(.+)", result.stdout, re.IGNORECASE)
    if match:
        return match.group(1).replace(":", "")
    return None


def get_cert_pubkey(openssl_cmd, cert):
    result = subprocess.run(
        [openssl_cmd, "x509", "-pubkey", "-noout", "-in", str(cert)],
        capture_output=True,
        text=True,
        check=False
    )
    return result.stdout.strip()


def is_cert_trusted(openssl_cmd, cert_file, trusted_cert_file):
    hash1 = get_cert_hash(openssl_cmd, cert_file)
    hash2 = get_cert_hash(openssl_cmd, trusted_cert_file)

    fp1 = get_cert_fingerprint(openssl_cmd, cert_file)
    fp2 = get_cert_fingerprint(openssl_cmd, trusted_cert_file)

    pk1 = get_cert_pubkey(openssl_cmd, cert_file)
    pk2 = get_cert_pubkey(openssl_cmd, trusted_cert_file)

    return hash1 == hash2 and fp1 == fp2 and pk1 == pk2


def verify_ocsp(openssl_cmd, cert_file, issuer_file, ocsp_dir):
    cname = extract_cn(openssl_cmd, cert_file)
    fingerprint = get_cert_fingerprint(openssl_cmd, cert_file)
    ocsp_response_file = Path(ocsp_dir) / fingerprint
    result = subprocess.run(
        [openssl_cmd, "ocsp", "-no_nonce",
         "-issuer", str(issuer_file),
         "-cert", str(cert_file),
         "-VAfile", str(issuer_file),
         "-respin", str(ocsp_response_file)],
        capture_output=True,
        text=True,
        check=False
    )
    expected_start = f"{cert_file}: good"

    if result.returncode != 0 or not result.stdout.startswith(expected_start):
        log_info(f"EC2 Instance Connect could not verify that certificate {cname} has not been revoked. No keys have been trusted.")
        sys.exit(1)


def verify_ocsp_chain(openssl_cmd, cert_files, ca_bundles_dir, ocsp_dir):
    for i in range(len(cert_files) - 1):
        cert_file = cert_files[i]
        subject = extract_cn(openssl_cmd, cert_file)
        if subject:
            trusted_cert_file = ca_bundles_dir / subject
            if trusted_cert_file.exists():
                if is_cert_trusted(openssl_cmd, cert_file, trusted_cert_file):
                    break
        issuer_file = cert_files[i+1]
        verify_ocsp(openssl_cmd, cert_file, issuer_file, ocsp_dir)


def get_ssh_key_fingerprint(key, tmpdir):
    key_file = Path(tmpdir) / "temp_key"
    key_file.write_text(f"{key}\n")

    log_info(f"DEBUG: Running ssh-keygen on {key_file}")
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", str(key_file)],
            capture_output=True,
            text=True,
            check=False,
            timeout=2
        )
        log_info(f"DEBUG: ssh-keygen completed, returncode={result.returncode}")
    except subprocess.TimeoutExpired:
        log_info("DEBUG: ssh-keygen timed out")
        key_file.unlink(missing_ok=True)
        return None

    key_file.unlink(missing_ok=True)

    if result.returncode != 0:
        log_info(f"DEBUG: ssh-keygen failed: {result.stderr}")
        return None

    parts = result.stdout.split()
    if len(parts) >= 2:
        return parts[1]
    return None


def verify_key_signature(openssl_cmd, signed_data, signature,
                         pubkey_file, tmpdir):
    signed_data_file = Path(tmpdir) / "signed_data"
    signed_data_file.write_text(signed_data)
    signed_data_file.chmod(0o400)

    try:
        sig_bytes = base64.b64decode(signature)
    except (base64.binascii.Error, ValueError):
        signed_data_file.unlink(missing_ok=True)
        return False

    sig_file = Path(tmpdir) / "decoded_sig"
    sig_file.write_bytes(sig_bytes)

    result = subprocess.run(
        [openssl_cmd, "dgst", "-sha256",
         "-sigopt", "rsa_padding_mode:pss",
         "-sigopt", "rsa_pss_saltlen:32",
         "-verify", str(pubkey_file),
         "-signature", str(sig_file),
         str(signed_data_file)],
        capture_output=True,
        check=False
    )

    signed_data_file.unlink(missing_ok=True)
    sig_file.unlink(missing_ok=True)

    return result.returncode == 0


def parse_key_entries(lines):
    METADATA_PREFIXES = {
        "#Timestamp=": "timestamp",
        "#Instance=": "instance_id",
        "#Caller=": "caller",
        "#Request=": "request"
    }
    i = 0

    while i < len(lines):
        while i < len(lines) and not lines[i].strip():
            i += 1

        if i >= len(lines):
            break

        metadata = {}
        signed_lines = []

        while i < len(lines) and lines[i].startswith("#"):
            line = lines[i].rstrip("\n")
            signed_lines.append(line)

            for prefix, key in METADATA_PREFIXES.items():
                if line.startswith(prefix):
                    metadata[key] = line[len(prefix):]
                    break
            i += 1

        if i >= len(lines) or not lines[i].startswith("ssh"):
            while i < len(lines) and lines[i].strip():
                i += 1
            continue

        key = lines[i].rstrip("\n")
        signed_lines.append(key)
        i += 1

        sig_parts = []
        while i < len(lines) and lines[i].strip():
            sig_parts.append(lines[i].rstrip("\n"))
            i += 1

        if sig_parts:
            yield {
                "key": key,
                "signature": "".join(sig_parts),
                "signed_data": "\n".join(signed_lines) + "\n",
                "metadata": metadata
            }


def process_keys(keys_path, current_instance_id, cur_time,
                 expected_key, openssl_cmd, pubkey_file, tmpdir):
    try:
        with open(keys_path, "r") as file:
            lines = file.readlines()
    except (FileNotFoundError, PermissionError, IOError) as e:
        log_info(f"Could not read keys file: {e}.")
        return []

    valid_keys = []

    for entry in parse_key_entries(lines):
        log_info("DEBUG: Processing entry")
        try:
            timestamp = int(entry["metadata"].get("timestamp", "0"))
            log_info(f"DEBUG: timestamp={timestamp}, cur_time={cur_time}")
            if timestamp == 0 or timestamp < cur_time:
                log_info("DEBUG: Skipping expired key")
                continue
        except ValueError:
            log_info("DEBUG: Invalid timestamp")
            continue

        if entry["metadata"].get("instance_id", "") != current_instance_id:
            log_info("DEBUG: Instance ID mismatch")
            continue

        log_info("DEBUG: Getting fingerprint")
        fingerprint = get_ssh_key_fingerprint(entry["key"], tmpdir)
        log_info(f"DEBUG: fingerprint={fingerprint}")
        if not fingerprint:
            log_info("DEBUG: Failed to get fingerprint")
            continue

        if expected_key and fingerprint != expected_key:
            log_info("DEBUG: Fingerprint mismatch")
            continue

        if not verify_key_signature(openssl_cmd, entry["signed_data"],
                                    entry["signature"], pubkey_file, tmpdir):
            log_info("DEBUG: Signature verification failed")
            continue

        msg = f"Providing ssh key from EC2 Instance Connect with fingerprint: {fingerprint}."
        if entry["metadata"].get("request"):
            msg += f", request-id: {entry['metadata']['request']}"
        if entry["metadata"].get("caller"):
            msg += f", for IAM principal: {entry['metadata']['caller']}"

        log_info(msg)
        valid_keys.append(entry["key"])

    return valid_keys


def main():
    # Set umask for temp file security
    os.umask(0o077)

    log_info("Parsing arguments.")
    args = parse_arguments()

    log_info("Verifying signer certificate.")

    log_info("Splitting the cert chain.")
    cert_files = split_cert_chain(args.signer, args.tmpdir)

    log_info("Building CA bundles dir.")
    ca_bundles_dir = build_ca_bundles_dir(
        args.openssl,
        cert_files,
        args.ca_path,
        args.tmpdir
    )

    log_info("Building CA trust chain.")
    ca_trust_file = build_ca_trust_chain(
        args.openssl,
        cert_files,
        args.ca_path,
        args.tmpdir,
        ca_bundles_dir
    )

    log_info("Verifying the CN.")
    signer_cn = extract_cn(args.openssl, cert_files[0])
    if signer_cn != args.expected_cn:
        log_info("EC2 Instance Connect encountered an unrecognised signer certificate. No keys have been trusted.")
        sys.exit(1)

    log_info("Verifying the trust chain.")
    verify_trust_chain(
        args.openssl,
        cert_files[0],
        args.ca_path,
        ca_trust_file
    )

    log_info("Verifying no certs have been revoked.")
    verify_ocsp_chain(
        args.openssl,
        cert_files,
        ca_bundles_dir,
        args.ocsp_dir_path
    )

    log_info("Removing the CA bundles dir.")
    shutil.rmtree(ca_bundles_dir, ignore_errors=True)

    log_info("Extracting signer public key.")
    pubkey = get_cert_pubkey(args.openssl, cert_files[0])
    if not pubkey:
        log_info("EC2 Instance Connect failed to extract the public key from the signer certificate. No keys have been trusted.")
        sys.exit(1)
    pubkey_file = Path(args.tmpdir) / "pubkey"
    pubkey_file.write_text(pubkey)

    if args.expected_key:
        log_info(f"Querying EC2 Instance Connect keys for matching fingerprint: {args.expected_key}")

    log_info("Setting current time as an expiration marker.")
    cur_time = int(time.time())

    log_info("Processing SSH keys.")
    valid_keys = process_keys(
        args.keys_path,
        args.current_instance_id,
        cur_time,
        args.expected_key,
        args.openssl,
        pubkey_file,
        args.tmpdir
    )

    if valid_keys:
        for key in valid_keys:
            print(key)
        sys.exit(0)
    sys.exit(255)


if __name__ == "__main__":
    main()

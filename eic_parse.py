#!/usr/bin/python3

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


def parse_arguments():
    parser = argparse.ArgumentParser()

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
            cert_path = os.path.join(tmpdir, f"cert{cert_count}.pem")
            with open(cert_path, "w") as f:
                f.write("\n".join(cur_cert) + "\n")
            certs.append(cert_path)
            cur_cert = []
            cert_count += 1

    return certs


def build_ca_bundles_dir(openssl_cmd, cert_files, ca_path, tmpdir):
    if os.path.isdir(ca_path):
        ca_path_dir = ca_path
    else:
        ca_path_dir = os.path.dirname(ca_path)

    ca_bundles_dir = tempfile.mkdtemp(prefix="eic-cert-", dir=tmpdir)

    if not cert_files:
        return ca_bundles_dir

    for i in range(1, len(cert_files)):
        cert_file = cert_files[i]
        subject = extract_cn(openssl_cmd, cert_file)
        if not subject:
            continue
        underscored = subject.replace(" ", "_")
        ca_cert = os.path.join(ca_path_dir, f"{underscored}.pem")
        if os.path.exists(ca_cert):
            shutil.copy(ca_cert, os.path.join(ca_bundles_dir, underscored))
        elif not os.path.isdir(ca_path):
            extract_from_bundle(ca_path, subject, ca_bundles_dir)

    return ca_bundles_dir


def extract_cn(openssl_cmd, cert_path):
    try:
        result = subprocess.run(
            [openssl_cmd, "x509", "-noout", "-subject", "-in", cert_path],
            capture_output=True,
            text=True,
            check=False,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        log_info("openssl x509 timed out extracting CN.")
        return None
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
                for cert_line in lines[i+1:]:
                    if cert_line.strip() and not cert_line.startswith("#"):
                        cert_lines.append(cert_line)
                    if "-----END CERTIFICATE-----" in cert_line:
                        break
                break

        if cert_lines and "-----END CERTIFICATE-----" in "\n".join(cert_lines):
            output_file = os.path.join(output_dir, subject)
            with open(output_file, "w") as f:
                f.write("\n".join(cert_lines) + "\n")

    except (FileNotFoundError, PermissionError, IOError) as e:
        log_info(f"Could not extract {subject} from bundle: {e}.")


def build_ca_trust_chain(cert_files, tmpdir, ca_bundles_dir):
    if len(cert_files) < 2:
        log_info("Certificate chain too short to build trust chain.")
        sys.exit(1)
    ca_trust_file = os.path.join(tmpdir, "ca-trust.pem")
    shutil.copy(cert_files[1], ca_trust_file)

    for entry in os.listdir(ca_bundles_dir):
        cert_file = os.path.join(ca_bundles_dir, entry)
        if os.path.isfile(cert_file):
            with open(cert_file, "r") as rf:
                content = rf.read()
            with open(ca_trust_file, "a") as af:
                af.write(content)

    os.chmod(ca_trust_file, 0o400)
    return ca_trust_file


def verify_trust_chain(openssl_cmd, cert_file, ca_path, ca_trust_file):
    if os.path.isdir(ca_path):
        cmd = [
            openssl_cmd, "verify", "-x509_strict",
            "-CApath", ca_path,
            "-CAfile", ca_trust_file,
            cert_file
        ]
    else:
        cmd = [
            openssl_cmd, "verify", "-x509_strict",
            "-CAfile", ca_trust_file,
            cert_file
        ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                check=False, timeout=5)
    except subprocess.TimeoutExpired:
        log_info("openssl verify timed out.")
        sys.exit(1)
    expected_output = f"{cert_file}: OK"

    if result.returncode != 0 or result.stdout.strip() != expected_output:
        log_info("EC2 Instance Connect could not verify the signer trust chain. No keys have been trusted.")
        sys.exit(1)


def get_cert_hash(openssl_cmd, cert):
    try:
        result = subprocess.run(
            [openssl_cmd, "x509", "-hash", "-noout", "-in", cert],
            capture_output=True,
            text=True,
            check=False,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        log_info("openssl x509 timed out getting cert hash.")
        return None
    return result.stdout.strip()


def get_cert_fingerprint(openssl_cmd, cert):
    try:
        result = subprocess.run(
            [openssl_cmd, "x509", "-fingerprint", "-sha1", "-noout",
             "-in", cert],
            capture_output=True,
            text=True,
            check=False,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        log_info("openssl x509 timed out getting fingerprint.")
        return None
    match = re.search(r"SHA1\s+Fingerprint\s*=\s*(.+)", result.stdout, re.IGNORECASE)
    if match:
        return match.group(1).replace(":", "")
    return None


def get_cert_pubkey(openssl_cmd, cert):
    try:
        result = subprocess.run(
            [openssl_cmd, "x509", "-pubkey", "-noout", "-in", cert],
            capture_output=True,
            text=True,
            check=False,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        log_info("openssl x509 timed out extracting public key.")
        return None
    return result.stdout.strip()


def is_cert_trusted(openssl_cmd, cert_file, trusted_cert_file):
    hash1 = get_cert_hash(openssl_cmd, cert_file)
    hash2 = get_cert_hash(openssl_cmd, trusted_cert_file)

    fp1 = get_cert_fingerprint(openssl_cmd, cert_file)
    fp2 = get_cert_fingerprint(openssl_cmd, trusted_cert_file)

    pk1 = get_cert_pubkey(openssl_cmd, cert_file)
    pk2 = get_cert_pubkey(openssl_cmd, trusted_cert_file)

    if None in (hash1, hash2, fp1, fp2, pk1, pk2):
      return False

    return hash1 == hash2 and fp1 == fp2 and pk1 == pk2


def verify_ocsp(openssl_cmd, cert_file, issuer_file, ocsp_dir):
    cname = extract_cn(openssl_cmd, cert_file)
    fingerprint = get_cert_fingerprint(openssl_cmd, cert_file)
    if not fingerprint:
        log_info("Failed to get certificate fingerprint for OCSP verification.")
        sys.exit(1)
    ocsp_response_file = os.path.join(ocsp_dir, fingerprint)
    try:
        result = subprocess.run(
            [openssl_cmd, "ocsp", "-no_nonce",
             "-issuer", issuer_file,
             "-cert", cert_file,
             "-VAfile", issuer_file,
             "-respin", ocsp_response_file],
            capture_output=True,
            text=True,
            check=False,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        log_info("openssl ocsp timed out.")
        sys.exit(1)
    expected_start = f"{cert_file}: good"

    if result.returncode != 0 or not result.stdout.startswith(expected_start):
        log_info(f"EC2 Instance Connect could not verify that certificate {cname} has not been revoked. No keys have been trusted.")
        sys.exit(1)


def verify_ocsp_chain(openssl_cmd, cert_files, ca_bundles_dir, ocsp_dir):
    for i in range(len(cert_files) - 1):
        cert_file = cert_files[i]
        subject = extract_cn(openssl_cmd, cert_file)
        if subject:
            trusted_cert_file = os.path.join(ca_bundles_dir, subject)
            if os.path.exists(trusted_cert_file):
                if is_cert_trusted(openssl_cmd, cert_file, trusted_cert_file):
                    break
        issuer_file = cert_files[i+1]
        verify_ocsp(openssl_cmd, cert_file, issuer_file, ocsp_dir)


def get_ssh_key_fingerprint(key, tmpdir):
    key_file = os.path.join(tmpdir, "temp_key")
    with open(key_file, "w") as f:
        f.write(f"{key}\n")

    log_info(f"Running ssh-keygen on {key_file}")
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", key_file],
            capture_output=True,
            text=True,
            check=False,
            timeout=2
        )
        log_info(f"ssh-keygen completed, returncode={result.returncode}")
    except subprocess.TimeoutExpired:
        log_info("ssh-keygen timed out")
        if os.path.exists(key_file):
            os.unlink(key_file)
        return None

    if os.path.exists(key_file):
        os.unlink(key_file)

    if result.returncode != 0:
        log_info(f"ssh-keygen failed: {result.stderr}")
        return None

    parts = result.stdout.split()
    if len(parts) >= 2:
        return parts[1]
    return None


def verify_key_signature(openssl_cmd, signed_data, signature,
                         pubkey_file, tmpdir):
    signed_data_file = os.path.join(tmpdir, "signed_data")
    with open(signed_data_file, "w") as f:
        f.write(signed_data)
    os.chmod(signed_data_file, 0o400)

    try:
        sig_bytes = base64.b64decode(signature)
    except (base64.binascii.Error, ValueError):
        if os.path.exists(signed_data_file):
            os.unlink(signed_data_file)
        return False

    sig_file = os.path.join(tmpdir, "decoded_sig")
    with open(sig_file, "wb") as f:
        f.write(sig_bytes)

    try:
        result = subprocess.run(
            [openssl_cmd, "dgst", "-sha256",
             "-sigopt", "rsa_padding_mode:pss",
             "-sigopt", "rsa_pss_saltlen:32",
             "-verify", pubkey_file,
             "-signature", sig_file,
             signed_data_file],
            capture_output=True,
            check=False,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        log_info("openssl dgst timed out verifying signature.")
        if os.path.exists(signed_data_file):
            os.unlink(signed_data_file)
        if os.path.exists(sig_file):
            os.unlink(sig_file)
        return False

    if os.path.exists(signed_data_file):
        os.unlink(signed_data_file)
    if os.path.exists(sig_file):
        os.unlink(sig_file)

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
        log_info("Processing entry")
        try:
            timestamp = int(entry["metadata"].get("timestamp", "0"))
            log_info(f"timestamp={timestamp}, cur_time={cur_time}")
            if timestamp == 0 or timestamp < cur_time:
                log_info("Skipping expired key")
                continue
        except ValueError:
            log_info("Invalid timestamp")
            continue

        if entry["metadata"].get("instance_id", "") != current_instance_id:
            log_info("Instance ID mismatch")
            continue

        log_info("Getting fingerprint")
        fingerprint = get_ssh_key_fingerprint(entry["key"], tmpdir)
        log_info(f"fingerprint={fingerprint}")
        if not fingerprint:
            log_info("Failed to get fingerprint")
            continue

        if expected_key and fingerprint != expected_key:
            log_info("Fingerprint mismatch")
            continue

        if not verify_key_signature(openssl_cmd, entry["signed_data"],
                                    entry["signature"], pubkey_file, tmpdir):
            log_info("Signature verification failed")
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
        cert_files,
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
    pubkey_file = os.path.join(args.tmpdir, "pubkey")
    with open(pubkey_file, "w") as f:
        f.write(pubkey)

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

#!/usr/bin/env python3

from pathlib import Path

import argparse
import os
import re
import shutil
import subprocess
import sys
import syslog
import tempfile


def log_info(message):
    print(f"LOG: {message}")
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


def main():
    # Set umask for temp file security
    os.umask(0o077)

    log_info("Parsing arguments.")
    args = parse_arguments()
    print("Arguments:")
    for arg, value in vars(args).items():
        print(f"{arg}: {value}")

    log_info("Verifying signer certificate.")
    cert_files = split_cert_chain(args.signer, args.tmpdir)
    print(f"Certs paths: {cert_files}")

    ca_bundles_dir = build_ca_bundles_dir(
        args.openssl,
        cert_files,
        args.ca_path,
        args.tmpdir
    )
    print(f"CA bundles dir: {ca_bundles_dir}")

    ca_trust_file = build_ca_trust_chain(
        args.openssl,
        cert_files,
        args.ca_path,
        args.tmpdir,
        ca_bundles_dir
    )
    print(f"CA trust file: {ca_trust_file}")


if __name__ == "__main__":
    main()

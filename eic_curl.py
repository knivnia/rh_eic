#!/usr/bin/python3

import atexit
import base64
import os
import pwd
import re
import shutil
import sys
import syslog
import tempfile

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

IMDS_URL = "http://169.254.169.254/latest/meta-data"
IMDS_TOKEN_URL = "http://169.254.169.254/latest/api/token"
IMDS_TIMEOUT = 3
TOKEN_HEADER = "X-aws-ec2-metadata-token"
VALID_DOMAINS = ["amazonaws.com",
                 "amazonaws.com.cn",
                 "c2s.ic.gov",
                 "sc2s.sgov.gov"]
MAX_RESPONSE_SIZE = 1024 * 1024


def log_info(message):
    syslog.syslog(syslog.LOG_AUTHPRIV | syslog.LOG_INFO, message)


def check_user_exists(username):
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def fetch_token():
    try:
        request = Request(
            IMDS_TOKEN_URL,
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "5"})
        with urlopen(request, timeout=IMDS_TIMEOUT) as response:
            token = response.read(MAX_RESPONSE_SIZE + 1).decode("utf-8").strip()
            if len(token) > MAX_RESPONSE_SIZE:
                log_info("IMDS response exceeds maximum allowed size.")
                sys.exit(255)
            if not token:
                log_info("EC2 Instance Connect failed to get a IMDS token.")
                sys.exit(255)
            return token
    except (URLError, HTTPError) as e:
        log_info(f"EC2 Instance Connect failed to establish trust with IMDS: {e}")
        sys.exit(255)


def fetch_instance_id(url, token):
    try:
        request = Request(url, headers={TOKEN_HEADER: token})
        with urlopen(request, timeout=IMDS_TIMEOUT) as response:
            instance_id = response.read(MAX_RESPONSE_SIZE + 1).decode("utf-8").strip()
            if len(instance_id) > MAX_RESPONSE_SIZE:
                log_info("IMDS response exceeds maximum allowed size.")
                sys.exit(255)
            return instance_id
    except (URLError, HTTPError):
        return None


def verify_instance_id(instance_id):
    if not instance_id or not isinstance(instance_id, str):
        return False
    return bool(re.match(r"^i-[0-9a-f]{8,32}$", instance_id))


def verify_ec2_instance(instance_id):
    hypervisor_uuid_path = "/sys/hypervisor/uuid"
    board_asset_tag_path = "/sys/devices/virtual/dmi/id/board_asset_tag"

    if os.path.isfile(hypervisor_uuid_path):
        # Xen instance
        try:
            with open(hypervisor_uuid_path, 'r') as file:
                uuid = file.read().strip()
            if uuid.startswith("ec2"):
                return
            else:
                log_info("EC2 Instance Connect was invoked on a non-instance.")
                sys.exit(0)
        except (IOError, OSError):
            log_info("EC2 Instance Connect failed to verify instance.")
            sys.exit(0)
    elif os.path.isfile(board_asset_tag_path):
        # Nitro instance
        try:
            with open(board_asset_tag_path, 'r') as file:
                board_asset_tag = file.read().strip()
            if board_asset_tag == instance_id:
                return
            else:
                log_info("Board asset tag does not match instance ID.")
                sys.exit(0)
        except (IOError, OSError):
            log_info("EC2 Instance Connect failed to verify instance.")
            sys.exit(0)
    else:
        log_info("EC2 Instance Connect was invoked on a non-instance.")
        sys.exit(0)


def check_active_keys(username, token):
    keys_url = f"{IMDS_URL}/managed-ssh-keys/active-keys/{username}/"
    try:
        request = Request(
            keys_url,
            method="HEAD",
            headers={TOKEN_HEADER: token}
        )
        with urlopen(request, timeout=IMDS_TIMEOUT):
            return True
    except HTTPError as e:
        log_info(f"HTTP error {e.code} while checking for active keys.")
        sys.exit(0)
    except URLError:
        log_info("Failed to check for active keys.")
        sys.exit(0)


def fetch_and_validate_az(token):
    az_url = f"{IMDS_URL}/placement/availability-zone/"
    try:
        request = Request(
            az_url,
            headers={TOKEN_HEADER: token}
        )
        with urlopen(request, timeout=IMDS_TIMEOUT) as response:
            zone = response.read(MAX_RESPONSE_SIZE + 1).decode("utf-8").strip()
            if len(zone) > MAX_RESPONSE_SIZE:
                log_info("IMDS response exceeds maximum allowed size.")
                sys.exit(255)
            if not re.match(r"^([a-z]+-){2,3}[0-9][a-z]$", zone):
                log_info("Invalid availability zone format.")
                sys.exit(255)
            return zone
    except (URLError, HTTPError):
        log_info("Failed to fetch availability zone.")
        sys.exit(255)


def extract_region_from_az(zone):
    match = re.match(r"(([a-z]+-)+[0-9]+)", zone)
    if match:
        return match.group(1)
    return None


def fetch_and_validate_domain(token):
    domain_url = f"{IMDS_URL}/services/domain/"
    try:
        request = Request(
            domain_url,
            headers={TOKEN_HEADER: token}
        )
        with urlopen(request, timeout=IMDS_TIMEOUT) as response:
            domain = response.read(MAX_RESPONSE_SIZE + 1).decode("utf-8").strip()
            if len(domain) > MAX_RESPONSE_SIZE:
                log_info("IMDS response exceeds maximum allowed size.")
                sys.exit(255)
            if domain not in VALID_DOMAINS:
                log_info("EC2 Instance Connect found an invalid domain.")
                sys.exit(255)
            return domain
    except (URLError, HTTPError):
        log_info("Failed to fetch domain from IMDS.")
        sys.exit(255)


def fetch_signer_cert(region, domain, token):
    expected_signer = f"managed-ssh-signer.{region}.{domain}"
    userpath = tempfile.mkdtemp(prefix='eic-', dir='/dev/shm')
    atexit.register(lambda: shutil.rmtree(userpath, ignore_errors=True))

    cert_url = f"{IMDS_URL}/managed-ssh-keys/signer-cert/"
    try:
        request = Request(
            cert_url,
            headers={TOKEN_HEADER: token}
        )
        with urlopen(request, timeout=IMDS_TIMEOUT) as response:
            cert = response.read(MAX_RESPONSE_SIZE + 1).decode("utf-8").strip()
            if len(cert) > MAX_RESPONSE_SIZE:
                log_info("IMDS response exceeds maximum allowed size.")
                sys.exit(255)
            if not cert:
                log_info("Failed to fetch the certificate.")
                sys.exit(1)
            cert_path = os.path.join(userpath, "signer-cert.pem")
            with open(cert_path, "w") as f:
                f.write(cert + "\n")
            return expected_signer, userpath, cert_path
    except (URLError, HTTPError) as e:
        log_info(f"Failed to fetch the signer certificate: {e}.")
        sys.exit(1)


def fetch_ocsp_staples(userpath, token):
    staples_url = f"{IMDS_URL}/managed-ssh-keys/signer-ocsp/"
    try:
        request = Request(
            staples_url,
            headers={TOKEN_HEADER: token}
        )
        with urlopen(request, timeout=IMDS_TIMEOUT) as response:
            staples_paths = response.read(MAX_RESPONSE_SIZE + 1).decode("utf-8").strip()
            if len(staples_paths) > MAX_RESPONSE_SIZE:
                log_info("IMDS response exceeds maximum allowed size.")
                sys.exit(255)
    except (URLError, HTTPError) as e:
        log_info(f"Failed to fetch OCSP staple paths: {e}.")
        sys.exit(1)

    ocsp_path = tempfile.mkdtemp(prefix='eic-ocsp-', dir=userpath)
    for path in staples_paths.split():
        if '/' in path or '\\' in path or path.startswith('.'):
            log_info(f"Invalid OCSP staple path component: {path}")
            sys.exit(1)
        safe_path = os.path.basename(path)
        staple_url = f"{IMDS_URL}/managed-ssh-keys/signer-ocsp/{path}"
        try:
            request = Request(
                staple_url,
                headers={TOKEN_HEADER: token}
            )
            with urlopen(request, timeout=IMDS_TIMEOUT) as response:
                decoded_data = base64.b64decode(response.read(MAX_RESPONSE_SIZE + 1))
                if len(decoded_data) > MAX_RESPONSE_SIZE:
                    log_info("IMDS response exceeds maximum allowed size.")
                    sys.exit(255)
                staple_file = os.path.join(ocsp_path, safe_path)
                if not os.path.realpath(staple_file).startswith(
                    os.path.realpath(ocsp_path)
                ):
                    log_info("OCSP staple path traversal detected.")
                    sys.exit(1)
                with open(staple_file, "wb") as file:
                    file.write(decoded_data)
                os.chmod(staple_file, 0o400)
        except (URLError, HTTPError) as e:
            log_info(f"Failed to fetch OCSP staple {path}: {e}.")
            sys.exit(1)
    return ocsp_path


def fetch_ssh_keys(username, userpath, token):
    keys_url = f"{IMDS_URL}/managed-ssh-keys/active-keys/{username}/"
    keys_file = os.path.join(userpath, 'eic-keys')
    try:
        request = Request(
            keys_url,
            headers={TOKEN_HEADER: token}
        )
        with urlopen(request, timeout=IMDS_TIMEOUT) as response:
            keys_data = response.read(MAX_RESPONSE_SIZE + 1).decode("utf-8")
            if len(keys_data) > MAX_RESPONSE_SIZE:
                log_info("IMDS response exceeds maximum allowed size.")
                sys.exit(255)
            with open(keys_file, 'w') as file:
                file.write(keys_data)
            return keys_file
    except (URLError, HTTPError) as e:
        log_info(f"Failed to fetch SSH keys: {e}.")
        sys.exit(1)


def call_parser(keys_file,
                userpath,
                cert_path,
                instance_id,
                expected_signer,
                ca_path,
                ocsp_path,
                fingerprint=None):
    import eic_parse

    exit_code = eic_parse.run(
        keys_path=keys_file,
        openssl="/usr/bin/openssl",
        tmpdir=userpath,
        signer_path=cert_path,
        current_instance_id=instance_id,
        expected_cn=expected_signer,
        ca_path=ca_path,
        ocsp_dir_path=ocsp_path,
        expected_key=fingerprint,
    )
    sys.exit(exit_code)


def main():
    # Set umask for temp file security
    os.umask(0o077)

    if len(sys.argv) < 2:
        log_info("EC2 Instance Connect was invoked without a user.")
        sys.exit(1)
    username = sys.argv[1]

    log_info("Verifying username.")
    if not check_user_exists(username):
        sys.exit(0)

    log_info("Fetching token from IMDS.")
    token = fetch_token()

    log_info("Fetching instance ID.")
    instance_id = fetch_instance_id(f"{IMDS_URL}/instance-id/", token)

    log_info("Verifying instance ID.")
    if not verify_instance_id(instance_id):
        log_info("Invalid instance ID.")
        sys.exit(0)

    log_info("Verifying EC2 instance.")
    verify_ec2_instance(instance_id)

    log_info("Checking active keys.")
    if check_active_keys(username, token):
        log_info(f"Active keys found for user {username}.")

    log_info("Validating the AZ.")
    zone = fetch_and_validate_az(token)

    region = extract_region_from_az(zone)

    log_info("Validating region and domain.")
    domain = fetch_and_validate_domain(token)

    log_info("Fetching signer certificate.")
    expected_signer, userpath, cert_path = fetch_signer_cert(region, domain, token)

    log_info("Fetching OCSP staples.")
    ocsp_path = fetch_ocsp_staples(userpath, token)

    log_info("Fetching SSH keys.")
    keys_file = fetch_ssh_keys(username, userpath, token)

    log_info("Calling parsing script.")
    ca_path = "/etc/pki/tls/certs"
    fingerprint = sys.argv[2] if len(sys.argv) > 2 else None
    call_parser(keys_file,
                userpath,
                cert_path,
                instance_id,
                expected_signer,
                ca_path,
                ocsp_path,
                fingerprint)


if __name__ == "__main__":
    main()

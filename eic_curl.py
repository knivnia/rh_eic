#!/usr/bin/env python3
import os
import sys
import syslog
import re
import pwd

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

TEST_MODE = os.getenv('EIC_TEST_MODE', 'false').lower() == 'true'

IMDS_URL = "http://169.254.169.254/latest/meta-data"
IMDS_TOKEN_URL = "http://169.254.169.254/latest/api/token"
IMDS_TIMEOUT = 1
TOKEN_HEADER = "X-aws-ec2-metadata-token"


def log_info(message):
    print(f"LOG: {message}")
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
            token = response.read().decode("utf-8").strip()
            if not token:
                log_info("EC2 Instance Connect failed to get a token to invoke Instance Metadata Service")
                sys.exit(255)
            return token
    except (URLError, HTTPError):
        log_info("EC2 Instance Connect failed to establish trust with Instance Metadata Service")
        sys.exit(255)


def fetch_instance_id(url, token):
    try:
        request = Request(url, headers={TOKEN_HEADER: token})
        with urlopen(request, timeout=IMDS_TIMEOUT) as response:
            instance_id = response.read().decode("utf-8").strip()
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
        print("Xen instance detected")
        try:
            with open(hypervisor_uuid_path, 'r') as f:
                uuid = f.read().strip()
                print(f"uuid: {uuid}")
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
        print("Nitro instance detected")
        try:
            with open(board_asset_tag_path, 'r') as f:
                board_asset_tag = f.read().strip()
                print(f"Board asset tag: {board_asset_tag}")
            if board_asset_tag == instance_id:
                return
            else:
                log_info("Board asset tag does not match instance ID.")
                sys.exit(0)
        except (IOError, OSError):
            log_info("EC2 Instance Connect failed to verify instance.")
            sys.exit(0)
    else:
        log_info("EC2 Instance Connect was invoked on a non-instance and will do nothing.")
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
        log_info(f"HTTP error {e.code} while checking for active keys")
        sys.exit(0)
    except URLError:
        log_info("Failed to check for active keys")
        sys.exit(0)


def main():
    # Set umask for temp file security
    os.umask(0o077)

    log_info("Checking for username argument")
    if len(sys.argv) < 2:
        log_info("EC2 Instance Connect was invoked without a user to authorise.")
        sys.exit(1)
    username = sys.argv[1]
    print(f"Username: {username}")

    log_info("Verifying username")
    if not check_user_exists(username):
        sys.exit(0)

    log_info("Fetching token from IMDS")
    token = fetch_token()
    print(f"Token: {token}")

    log_info("Fetching instance ID")
    instance_id = fetch_instance_id(f"{IMDS_URL}/instance-id/", token)
    print(f"Instance ID: {instance_id}")

    log_info("Verifying instance ID")
    if not verify_instance_id(instance_id):
        log_info("Invalid instance ID")
        sys.exit(0)
    print("Instance ID verified")

    log_info("Verifying EC2 instance")
    verify_ec2_instance(instance_id)
    print("Instance verified")

    log_info("Checking active keys")
    if check_active_keys(username, token):
        print("Active keys found")
        log_info(f"Active keys found for user {username}")


if __name__ == "__main__":
    main()

#!/usr/bin/python3

import re
import subprocess
import sys
import syslog

EXIT_FAILURE = 1
EXIT_TIMEOUT = 124
EXIT_NOT_FOUND = 127

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9._-]{0,31}$")


def log_info(message):
    syslog.syslog(syslog.LOG_AUTHPRIV | syslog.LOG_INFO, message)


def validate_username(username):
    return USERNAME_RE.match(username) is not None


def main():
    log_info("Checking for username argument.")
    if len(sys.argv) < 2:
        log_info("EC2 Instance Connect was invoked without a user.")
        sys.exit(EXIT_FAILURE)
    username = sys.argv[1]

    if not validate_username(username):
        log_info(f"Invalid username format")
        sys.exit(EXIT_FAILURE)

    command = [sys.executable, "-m",
               "ec2_instance_connect_rhel.eic_curl"] + sys.argv[1:]

    try:
        result = subprocess.run(command, capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        log_info("EC2 Instance Connect timed out.")
        sys.exit(EXIT_TIMEOUT)

    if result.stdout:
        sys.stdout.buffer.write(result.stdout)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()

#!/usr/bin/python3

import os
import re
import subprocess
import sys
import syslog


USERNAME_RE = re.compile(r"^[a-z_][a-z0-9._-]{0,31}$")


def log_info(message):
    syslog.syslog(syslog.LOG_AUTHPRIV | syslog.LOG_INFO, message)


def validate_username(username):
    return USERNAME_RE.match(username) is not None


def main():
    log_info("Checking that script is present.")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(script_dir, "eic_curl.py")
    if not os.path.isfile(script):
        sys.stderr.write(f"Error: {script} not found\n")
        sys.exit(127)

    log_info("Checking for username argument.")
    if len(sys.argv) < 2:
        log_info("EC2 Instance Connect was invoked without a user.")
        sys.exit(1)
    username = sys.argv[1]

    if not validate_username(username):
        log_info(f"Invalid username format")
        sys.exit(1)


    command = [sys.executable, script] + sys.argv[1:]

    try:
        result = subprocess.run(command, timeout=15)
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        sys.stderr.write("Timeout expired\n")
        sys.exit(0)


if __name__ == "__main__":
    main()

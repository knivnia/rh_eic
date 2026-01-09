#!/usr/bin/env python3
"""
Wrapper for eic_curl.py with timeout.
Necessary for older versions of openssh where AuthorizedKeysCommand must be a filepath.
"""

import os
import subprocess
import sys

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(script_dir, "eic_curl.py")

    if not os.path.isfile(script):
        sys.stderr.write(f"Error: {script} not found\n")
        sys.exit(127)

    command = [sys.executable, script] + sys.argv[1:]

    try:
        result = subprocess.run(command, timeout=5)
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        sys.exit(0)

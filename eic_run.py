#!/usr/bin/python3

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
        result = subprocess.run(command, timeout=15)
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        sys.stderr.write("Timeout expired")
        sys.exit(0)

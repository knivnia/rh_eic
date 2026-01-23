#!/usr/bin/env python3

import argparse
import os
import sys
import syslog


def log_info(message):
    print(f"LOG: {message}")
    syslog.syslog(syslog.LOG_AUTHPRIV | syslog.LOG_INFO, message)


def str_to_bool(word):
    if word.lower() == "true":
        return True
    elif word.lower() == "false":
        return False
    else:
        raise argparse.ArgumentTypeError(f"Boolean expected ('true'. or 'false'), got {word}")


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


def main():
    # Set umask for temp file security
    os.umask(0o077)

    log_info("Parsing arguments")
    args = parse_arguments()
    print("Arguments:")
    for arg, value in vars(args).items():
        print(f"{arg}: {value}")


if __name__ == "__main__":
    main()

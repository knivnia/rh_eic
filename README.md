# ec2-instance-connect-rhel

EC2 Instance Connect implementation for RHEL and Fedora.

Retrieves and validates SSH public keys from the AWS Instance Metadata
Service (IMDS) so that sshd can authorize EC2 Instance Connect sessions.

## How it works

sshd calls `eic-run` as an `AuthorizedKeysCommand`. The call chain is:

1. **eic-run** -- validates the username, launches eic-curl as a subprocess
   with a 5-second timeout.
2. **eic-curl** -- fetches the IMDS token, instance identity, signer
   certificate, OCSP staples, and SSH keys. Calls eic-parse in-process.
3. **eic-parse** -- verifies the certificate trust chain and OCSP status,
   validates key signatures, and prints valid keys to stdout.

## Install (development)

```
pip install -e .
```

This puts `eic-run`, `eic-curl`, and `eic-parse` on your PATH.

## Run tests

```
pytest
```

## Install on an EC2 instance

Build the wheel, copy it to the instance, and run the install script:

```bash
# Local machine
python3 -m build
scp -i <key.pem> dist/*.whl install-on-instance.sh ec2-user@<ip>:/tmp/

# On the instance
sudo /tmp/install-on-instance.sh
```

The script installs the package, configures the sshd drop-in, and walks
through SELinux policy setup.

## Project layout

```
src/ec2_instance_connect_rhel/
    __init__.py
    eic_run.py      Entry point (AuthorizedKeysCommand)
    eic_curl.py     IMDS communication
    eic_parse.py    Certificate and key verification
tests/
    test_eic_run.py
    test_eic_curl.py
    test_eic_parse.py
```

## Exit codes

| Code | Constant              | Meaning                                              |
|------|-----------------------|------------------------------------------------------|
| 0    | EXIT_SUCCESS          | Keys printed, or soft skip (missing user, non-EC2)   |
| 1    | EXIT_FAILURE          | Validation or trust-chain failure                    |
| 124  | EXIT_TIMEOUT          | eic-run subprocess timed out (5s)                    |
| 255  | EXIT_ERROR            | IMDS/protocol error, or no valid keys found          |

## License

Apache-2.0

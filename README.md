# ec2-instance-connect-rhel

EC2 Instance Connect for RHEL and Fedora.

Retrieves and validates SSH public keys from the AWS Instance Metadata
Service (IMDS) so that sshd can authorize EC2 Instance Connect sessions.

## How it works

sshd calls `eic-run` as an `AuthorizedKeysCommand`. The call chain is:

1. **eic-run** — validates the username, launches eic-curl as a subprocess
   with a 5-second timeout.
2. **eic-curl** — fetches the IMDS token, instance identity, signer
   certificate, OCSP staples, and SSH keys. Calls eic-parse in-process.
3. **eic-parse** — verifies the certificate trust chain and OCSP status,
   validates key signatures, and prints valid keys to stdout.

The RPM installs:

- `/usr/bin/eic-run`, `eic-curl`, `eic-parse`
- `/etc/ssh/sshd_config.d/60-ec2-instance-connect.conf`
- locked system user `ec2-instance-connect` (`AuthorizedKeysCommandUser`)

## Install on RHEL 10/ Fedora

```bash
sudo dnf -y copr enable knivnia/rh-eic && sudo dnf -y install ec2-instance-connect-rhel
```

Project: [copr.fedorainfracloud.org/coprs/knivnia/rh-eic](https://copr.fedorainfracloud.org/coprs/knivnia/rh-eic/)

Use a Copr chroot that matches the instance (for RHEL 10 x86_64, builds for
`epel-10-x86_64` / equivalent). After install, try EC2 Instance Connect from
the AWS console or `aws ec2-instance-connect ssh --instance-id=<instance ID>`.


## Project layout

```
src/ec2_instance_connect_rhel/
    eic_run.py      Entry point (AuthorizedKeysCommand)
    eic_curl.py     IMDS communication
    eic_parse.py    Certificate and key verification
conf/
    60-ec2-instance-connect.conf   sshd drop-in (packaged)
ec2-instance-connect-rhel.spec     RPM spec
tests/
```

## Exit codes

| Code | Constant       | Meaning                                            |
|------|----------------|----------------------------------------------------|
| 0    | EXIT_SUCCESS   | Keys printed, or soft skip (missing user, non-EC2) |
| 1    | EXIT_FAILURE   | Validation or trust-chain failure                  |
| 124  | EXIT_TIMEOUT   | eic-run subprocess timed out (5s)                  |
| 255  | EXIT_ERROR     | IMDS/protocol error, or no valid keys found        |

## License

Apache-2.0

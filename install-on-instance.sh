#!/bin/bash
# Install EC2 Instance Connect package on a RHEL instance (TESTING.md steps 2-5).
#
# Usage (on the instance, as root):
#   sudo ./install-on-instance.sh                          # wheel already in /tmp
#   sudo ./install-on-instance.sh /path/to/package.whl     # explicit wheel path
#
# Copy to the instance together with the install script:
#   scp -i <key.pem> dist/*.whl install-on-instance.sh ec2-user@<ip>:/tmp/

set -euo pipefail

SSHD_DROPIN="/etc/ssh/sshd_config.d/60-eic.conf"
SELINUX_MODULE="eic_sshd"

log() {
    printf '==> %s\n' "$*"
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "run as root (e.g. sudo $0)"
    fi
}

find_wheel() {
    if [[ -n "${1:-}" ]]; then
        [[ -f "$1" ]] || die "wheel not found: $1"
        WHEEL="$1"
    else
        # Find the newest .whl in /tmp
        WHEEL="$(ls -t /tmp/ec2_instance_connect_rhel-*.whl 2>/dev/null | head -1)"
        [[ -n "${WHEEL}" ]] || die "no wheel found in /tmp (copy the .whl there first)"
    fi
}

install_package() {
    if ! command -v pip3 >/dev/null 2>&1; then
        log "pip3 not found, installing python3-pip"
        dnf install -y python3-pip ||
            die "failed to install python3-pip"
    fi

    log "Installing package from ${WHEEL}"
    pip3 install --force-reinstall --no-warn-script-location \
        --break-system-packages "${WHEEL}" ||
        die "pip3 install failed"

    # pip may install scripts to /usr/local/bin which is not always on PATH
    export PATH="/usr/local/bin:${PATH}"

    # Verify the entry point exists
    EIC_RUN="$(which eic-run 2>/dev/null)" ||
        die "eic-run entry point not found after install"
    log "Entry point installed at ${EIC_RUN}"
}

configure_sshd() {
    log "Configuring sshd drop-in at ${SSHD_DROPIN}"
    mkdir -p /etc/ssh/sshd_config.d

    local eic_run_path
    eic_run_path="$(which eic-run)"

    cat >"${SSHD_DROPIN}" <<EOF
AuthorizedKeysCommand ${eic_run_path} %u %f
AuthorizedKeysCommandUser root
EOF
    chmod 600 "${SSHD_DROPIN}"

    log "Validating and restarting sshd"
    sshd -t
    systemctl restart sshd
}

fix_selinux() {
    if ! command -v getenforce >/dev/null 2>&1; then
        log "SELinux tools not found; skipping SELinux policy step"
        return 0
    fi

    local mode
    mode="$(getenforce)"
    if [[ "${mode}" == "Disabled" ]]; then
        log "SELinux is disabled; skipping policy step"
        return 0
    fi

    command -v ausearch >/dev/null 2>&1 ||
        die "ausearch not found (install audit package)"
    command -v audit2allow >/dev/null 2>&1 ||
        die "audit2allow not found (install policycoreutils-python-utils)"
    command -v semodule >/dev/null 2>&1 ||
        die "semodule not found (install policycoreutils-python-utils)"

    log "Setting SELinux to Permissive (temporary)"
    setenforce 0

    cat <<'EOF'

Connect via the EC2 Instance Connect web UI once now.
That generates the AVC denials needed for the local policy module.

EOF
    read -r -p "Press Enter after connecting via the web UI... " _

    log "Building and loading SELinux policy module ${SELINUX_MODULE}"
    ausearch -m avc | audit2allow -M "${SELINUX_MODULE}"
    semodule -i "${SELINUX_MODULE}.pp"

    log "Re-enabling SELinux Enforcing mode"
    setenforce 1
}

verify() {
    log "Verifying sshd AuthorizedKeysCommand configuration"
    sshd -T | grep -i authorizedkeyscommand

    if command -v getenforce >/dev/null 2>&1; then
        log "SELinux mode: $(getenforce)"
    fi

    log "Installed package:"
    pip3 show ec2-instance-connect-rhel

    log "Entry points:"
    which eic-run eic-curl eic-parse
}

main() {
    require_root
    find_wheel "${1:-}"
    install_package
    configure_sshd
    fix_selinux
    verify
    log "Done."
}

main "$@"

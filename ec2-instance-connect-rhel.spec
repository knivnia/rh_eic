# RPM / project name (hyphens)
%global pkgname ec2-instance-connect-rhel
# setuptools sdist directory / filename (underscores)
%global srcname ec2_instance_connect_rhel

Name:           %{pkgname}
Version:        0.0.1
Release:        %autorelease
Summary:        EC2 Instance Connect for RHEL

License:        Apache-2.0
# FIX
URL:            https://github.com/.../%{pkgname}
# FIX
Source0:        %{srcname}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel
BuildRequires:  python3-pytest
BuildRequires:  openssl
BuildRequires:  openssh-clients
Requires:       python3
Requires:       openssh-server
Requires:       openssl
Requires:       ca-certificates
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): shadow-utils

%description
Provides AuthorizedKeysCommand helpers so OpenSSH on RHEL/Fedora can accept
short-lived SSH public keys from Amazon EC2 Instance Connect (via IMDS).

The package installs an sshd_config.d drop-in and runs the helpers as the
locked system user ec2-instance-connect.


%prep
%autosetup -p1 -n %{srcname}-%{version}


%generate_buildrequires
%pyproject_buildrequires


%build
%pyproject_wheel


%install
%pyproject_install
%pyproject_save_files %{srcname}

install -D -p -m 0644 conf/60-ec2-instance-connect.conf \
    %{buildroot}%{_sysconfdir}/ssh/sshd_config.d/60-ec2-instance-connect.conf


%check
%pytest


%pre
# Create locked system user used by AuthorizedKeysCommandUser
getent passwd ec2-instance-connect >/dev/null || \
    useradd -r -M -s %{_sbindir}/nologin -d %{_tmppath} ec2-instance-connect
usermod -L ec2-instance-connect >/dev/null 2>&1 || :


%post
if [ -x /usr/sbin/sshd ]; then
    /usr/sbin/sshd -t >/dev/null 2>&1 || :
fi
if [ -x /usr/bin/systemctl ] && systemctl is-active --quiet sshd; then
    systemctl try-restart sshd.service >/dev/null 2>&1 || :
fi


%preun
if [ "$1" -eq 0 ] && [ -x /usr/bin/systemctl ] && systemctl is-active --quiet sshd; then
    systemctl try-restart sshd.service >/dev/null 2>&1 || :
fi


%postun
if [ "$1" -eq 0 ]; then
    userdel ec2-instance-connect >/dev/null 2>&1 || :
    if [ -x /usr/bin/systemctl ] && systemctl is-active --quiet sshd; then
        systemctl try-restart sshd.service >/dev/null 2>&1 || :
    fi
fi


%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/eic-run
%{_bindir}/eic-curl
%{_bindir}/eic-parse
%config(noreplace) %{_sysconfdir}/ssh/sshd_config.d/60-ec2-instance-connect.conf


%changelog
%autochangelog

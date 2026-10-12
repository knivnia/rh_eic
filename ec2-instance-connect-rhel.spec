%global pkgname ec2-instance-connect-rhel
%global srcname ec2_instance_connect_rhel
%global selinuxtype targeted
%global modulename ec2instanceconnect
%global with_selinux 1

%if 0%{?rhel} == 9
%global python3_pkgversion 3.12
%endif

Name:           %{pkgname}
Version:        0.0.1
Release:        %autorelease
Summary:        EC2 Instance Connect for RHEL

License:        Apache-2.0
URL:            https://github.com/.../%{pkgname}
Source0:        %{srcname}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-setuptools
BuildRequires:  python%{python3_pkgversion}-wheel
BuildRequires:  python%{python3_pkgversion}-pytest
BuildRequires:  openssl
BuildRequires:  openssh-clients
BuildRequires:  selinux-policy-devel
Requires:       python%{python3_pkgversion}
Requires:       openssh-server
Requires:       openssl
Requires:       ca-certificates
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): shadow-utils
%if 0%{?with_selinux}
Requires:       (%{name}-selinux if selinux-policy-%{selinuxtype})
%endif

%description
Provides AuthorizedKeysCommand helpers so OpenSSH on RHEL/Fedora can accept
short-lived SSH public keys from Amazon EC2 Instance Connect (via IMDS).

The package installs an sshd_config.d drop-in and runs the helpers as the
locked system user ec2-instance-connect. On SELinux systems the helper
runs in the eic_t domain.


%if 0%{?with_selinux}
%package selinux
Summary:        SELinux policy for %{name}
BuildArch:      noarch
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
%{?selinux_requires_min}

%description selinux
Confines the EC2 Instance Connect AuthorizedKeysCommand helper in the
eic_t domain.
%endif


%prep
%autosetup -p1 -n %{srcname}-%{version}


%generate_buildrequires
%pyproject_buildrequires


%build
%pyproject_wheel

%if 0%{?with_selinux}
make -f %{_datadir}/selinux/devel/Makefile -C selinux %{modulename}.pp
bzip2 -9 selinux/%{modulename}.pp
%endif


%install
%pyproject_install
%pyproject_save_files %{srcname}

install -D -p -m 0644 conf/60-ec2-instance-connect.conf \
    %{buildroot}%{_sysconfdir}/ssh/sshd_config.d/60-ec2-instance-connect.conf

mkdir -p %{buildroot}%{_sysconfdir}/systemd/system/sshd.service.d
ln -s /dev/null \
    %{buildroot}%{_sysconfdir}/systemd/system/sshd.service.d/ec2-instance-connect.conf

%if 0%{?with_selinux}
install -D -m 0644 selinux/%{modulename}.pp.bz2 \
    %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
install -D -p -m 0644 selinux/%{modulename}.if \
    %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{modulename}.if
%endif


%check
%pytest


%pre
getent passwd ec2-instance-connect >/dev/null || \
    useradd -r -M -s %{_sbindir}/nologin -d %{_tmppath} ec2-instance-connect
usermod -L ec2-instance-connect >/dev/null 2>&1 || :


%post
if [ -x /usr/sbin/sshd ]; then
    /usr/sbin/sshd -t >/dev/null 2>&1 || :
fi


%posttrans
if [ -x /usr/bin/systemctl ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if systemctl is-active --quiet sshd; then
        systemctl try-restart sshd.service >/dev/null 2>&1 || :
    fi
fi


%preun
if [ "$1" -eq 0 ] && [ -x /usr/bin/systemctl ] && systemctl is-active --quiet sshd; then
    systemctl try-restart sshd.service >/dev/null 2>&1 || :
fi


%postun
if [ "$1" -eq 0 ]; then
    userdel ec2-instance-connect >/dev/null 2>&1 || :
    if [ -x /usr/bin/systemctl ]; then
        systemctl daemon-reload >/dev/null 2>&1 || :
        if systemctl is-active --quiet sshd; then
            systemctl try-restart sshd.service >/dev/null 2>&1 || :
        fi
    fi
fi


%if 0%{?with_selinux}
%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
if [ -e /etc/selinux/config ]; then
    . /etc/selinux/config
fi
if [ "${SELINUXTYPE:-}" = "%{selinuxtype}" ]; then
    rm -rf %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/400/extra_varrun || :
    semodule -n -s %{selinuxtype} -X 200 -i %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "ec2instanceconnect: failed to install SELinux module (semodule exit $rc)" >&2
        exit "$rc"
    fi
    selinuxenabled && load_policy || :
    %{_libexecdir}/selinux/varrun-convert.sh %{selinuxtype} || :
fi

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}
%endif


%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/eic-run
%{_bindir}/eic-curl
%{_bindir}/eic-parse
%config(noreplace) %{_sysconfdir}/ssh/sshd_config.d/60-ec2-instance-connect.conf
%{_sysconfdir}/systemd/system/sshd.service.d/ec2-instance-connect.conf


%if 0%{?with_selinux}
%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.*
%{_datadir}/selinux/devel/include/distributed/%{modulename}.if
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{modulename}
%endif


%changelog
%autochangelog

%global debug_package %{nil}

Name:           colatrl
Version:        1.1
Release:        1%{?dist}
Summary:        BPF-based CLAT (464XLAT) implementation
License:        Apache-2.0
Source0:        colatrl-%{version}.tar.gz
BuildRequires:  clang gcc gcc-c++ make glibc-devel(x86-32) libgcc(x86-32)
BuildRequires:  systemd-rpm-macros
Requires:       bpftool iproute ndisc6 bind-utils
%{?systemd_requires}

%description
colatrl is an experimental BPF-based CLAT implementation for IPv6-only
networks with NAT64/DNS64. It uses tc BPF programs (colatrld.o, compiled
with clang -target bpf) to translate between IPv4 and IPv6 packets in the
kernel fast path.

%prep
%autosetup

%build
make

%install
mkdir -p %{buildroot}/usr/sbin
make install DESTDIR=%{buildroot}
install -D -m 0644 debian/colatrl.service \
  %{buildroot}%{_unitdir}/colatrl.service

%post
%systemd_post colatrl.service

%preun
%systemd_preun colatrl.service

%postun
%systemd_postun_with_restart colatrl.service

%files
%license LICENSE
/usr/lib/colatrl/colatrld.o
/usr/sbin/colatrlutil
/usr/sbin/colatrl
%{_unitdir}/colatrl.service

%changelog
* Sun Apr 12 2026 colatrl <colatrl@colatrl> - 1.1-1
- Initial RPM package.

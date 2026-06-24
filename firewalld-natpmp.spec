Name:           firewalld-natpmp
Version:        1.0.0
Release:        1%{?dist}
Summary:        Native D-Bus NAT-PMP daemon for firewalld

License:        GPL-3.0-or-later
URL:            https://github.com/salmanshafi/firewalld-natpmp
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.18
BuildRequires:  systemd-rpm-macros
Requires:       firewalld

%description
firewalld-natpmp is a lightweight NAT-PMP (RFC 6886) daemon designed exclusively for
firewalld environments. By communicating natively via the firewalld D-Bus API
and offloading lease timeouts to the kernel, it eliminates netfilter hook
conflicts and orphaned rules common in legacy UPnP/PCP daemons.

%prep
%autosetup

%build
export CGO_ENABLED=0
export GO111MODULE=on

# The compiler will automatically download dependencies here
go build -buildmode=pie -ldflags="-s -w -extldflags '-static'" -o %{name} main.go

%install
install -Dpm 0755 %{name} %{buildroot}%{_sbindir}/%{name}
install -Dpm 0644 config.yaml %{buildroot}%{_sysconfdir}/%{name}/config.yaml
install -Dpm 0644 %{name}.service %{buildroot}%{_unitdir}/%{name}.service

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%license LICENSE
%doc README.md
%{_sbindir}/%{name}
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/config.yaml
%{_unitdir}/%{name}.service

%changelog
* Wed Jun 24 2026 Salman Shafi <hello@salmanshafi.net> - 1.0.0-1
- Initial public release
- Implement D-Bus API integration for firewalld NAT-PMP mapping
- Add client rate-limiting, timeout offloading, and privileged port protection

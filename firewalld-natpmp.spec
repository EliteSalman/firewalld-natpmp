%global debug_package %{nil}

Name:           firewalld-natpmp
Version:        1.2.1
Release:        1%{?dist}
Summary:        Native D-Bus NAT-PMP daemon for firewalld

License:        GPL-3.0-or-later
URL:            https://github.com/EliteSalman/%{name}
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.18
BuildRequires:  systemd-rpm-macros
Requires:       firewalld

%description
firewalld-natpmp is a lightweight NAT-PMP (RFC 6886) daemon designed exclusively for
firewalld environments. By communicating natively via the firewalld D-Bus API
and offloading lease timeouts to the kernel, it eliminates netfilter hook
conflicts and orphaned rules common in legacy UPnP/PCP daemons.

%prep
%autosetup -n %{name}-%{version}

%build
export CGO_ENABLED=0
export GO111MODULE=on
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
* Fri Jun 26 2026 Salman Shafi <elitesalman@fedoraproject.org> - 1.2.1-1
- Update to upstream version 1.2.1
- Complete implementation of durability, reload resilience, and graceful shutdown features
- Add RuntimeDirectory to systemd service file to satisfy ProtectSystem=strict constraints
- Relocate internal state JSON destination to /run/firewalld-natpmp/state.json

* Fri Jun 26 2026 Salman Shafi <hello@salmanshafi.net> - 1.2.0-1
- Decoupled NAT rule lifecycle from firewalld timeouts using zero-timeout permanent rules and internal timers
- Implemented D-Bus Reloaded signal interception for automatic runtime state recovery
- Added namespace isolation via JSON state file (/var/run/firewalld-natpmp.json) to preserve external admin rules
- Added graceful shutdown handling (SIGINT/SIGTERM) to actively flush daemon-managed D-Bus port forwards before exit
- Fixed RFC 6886 compliance bug resolving -52 timeout hangs by padding OpCode 1/2 error responses to 16 bytes
- Fixed network micro-outages during lease renewals by bypassing D-Bus execution on active mappings

* Thu Jun 25 2026 Salman Shafi <hello@salmanshafi.net> - 1.1.0-1
- Overhaul daemon architecture to patch critical concurrency data races and bounded resource leaks
- Implement strict RFC 6886 §3.3 protocol handling for ephemeral port allocation and client teardowns
- Introduce worker pool limits and optional subnet filtering for hardening against UDP exploitation
- Resolve memory state desynchronisation on D-Bus transaction errors via two-phase commit updates

* Wed Jun 24 2026 Salman Shafi <hello@salmanshafi.net> - 1.0.1-1
- Fix systemd service not enabling due to missing WantedBy target

* Wed Jun 24 2026 Salman Shafi <hello@salmanshafi.net> - 1.0.0-1
- Initial public release

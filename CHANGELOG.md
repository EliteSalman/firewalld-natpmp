# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2026-06-24
### Fixed
- Added `WantedBy=multi-user.target` to systemd service unit to allow proper enabling/starting via `systemctl`.

## [1.0.0] - 2026-06-24
- Initial public release
- Native D-Bus integration for firewalld
- Implemented RFC 6886 NAT-PMP support
- Security hardening: rate-limiting and privileged port protection
- Fedora COPR support included


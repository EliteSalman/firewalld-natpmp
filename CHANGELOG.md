# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2026-06-26

### Added
* Implemented firewalld reload detection via D-Bus `Reloaded` signal. The daemon now automatically intercepts administrator-triggered reloads and restores its active NAT-PMP leases directly back into the runtime environment without waiting for client renewals.
* Introduced namespace isolation through a JSON-based recovery state file (`/var/run/firewalld-natpmp.json`). The daemon strictly tracks its own injected rules, ensuring it never flushes or interferes with external NAT rules explicitly added by system administrators.
* Implemented graceful shutdown handling via `os/signal`. Intercepts `SIGINT` and `SIGTERM` to proactively flush active D-Bus port forwarding rules from Firewalld before daemon termination.

### Changed
* Decoupled NAT rule lifecycle management from Firewalld's internal timeout mechanism. D-Bus port forwarding rules are now injected into the runtime environment as permanent (timeout `0`).
* Shifted all lease expiration and teardown execution to the Go daemon's internal memory space using asynchronous `time.AfterFunc` timers.
* Adjusted the startup sanitisation routine to rely solely on the isolated JSON recovery state, removing blind broad-scope D-Bus forward port flushing.

### Fixed
* Resolved a routing micro-outage bug triggered during standard lease renewals. Renewal requests for active mappings now strictly update the in-memory timer and bypass the D-Bus execution barrier, preventing `netfilter` drop gaps.
* Fixed an RFC 6886 compliance violation where `sendError` generated truncated 8-byte payloads. Error responses for OpCodes 1 and 2 are now correctly padded to the mandated 16 bytes, resolving `-52` (`NATPMP_ERR_RECVFROM`) timeout hangs in strict clients.

## [1.1.0] - 2026-06-25

### Added
- Implemented a configurable worker pool (`worker_pool_size`) to throttle concurrent packet execution and eliminate Denial of Service (DoS) vectors via unbounded goroutines.
- Added an optional `allowed_subnet` configuration parameter to enforce strict client source IP subnet restrictions.
- Added a `public_ip` configuration option to explicitly override and define the external IP advertised to NAT-PMP clients, resolving incorrect local interface route disclosures.
- Implemented global port mapping tracking (`globalPorts`) to explicitly detect and prevent cross-client port collisions.

### Changed
- Re-architected state mutation into a phased transaction commit pattern, ensuring system configuration executes fully before memory states are altered to prevent desync on D-Bus failures.
- Transitioned global `sysBus` handling to a thread-safe implementation using a read-write mutex (`sync.RWMutex`) to prevent data races during multi-client operations or firewalld service restarts.

### Fixed
- Brought external port allocation into full compliance with RFC 6886 §3.3 by generating a random available ephemeral port when a client requests `extPort == 0`.
- Implemented complete mapping teardown logic according to RFC 6886 when an internal port of `0` or an explicit dual-zero configuration is received.


## [1.0.1] - 2026-06-24
### Fixed
- Added `WantedBy=multi-user.target` to systemd service unit to allow proper enabling/starting via `systemctl`.

## [1.0.0] - 2026-06-24
- Initial public release
- Native D-Bus integration for firewalld
- Implemented RFC 6886 NAT-PMP support
- Security hardening: rate-limiting and privileged port protection
- Fedora COPR support included


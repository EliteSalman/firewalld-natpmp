# fw-natpmp

`fw-natpmp` is a lightweight, conflict-free NAT-PMP (RFC 6886) daemon built specifically for modern Linux routers using `firewalld`. 

Legacy tools like `miniupnpd` were designed before `nftables` and `firewalld` became the standard. They hijack kernel netfilter hooks, which regularly causes conflicts with WireGuard routing, interface masquerading, and firewall reloads. `fw-natpmp` solves this by acting as a native extension to the `firewalld` ecosystem.

## Architecture & Features

* **Native D-Bus Integration:** Instead of executing slow shell commands or manipulating kernel tables directly, `fw-natpmp` communicates exclusively through the `firewalld` D-Bus socket.
* **Zero Orphaned Rules:** Rule expiration is offloaded entirely to `firewalld`'s internal timer engine. If the daemon crashes, `firewalld` will still securely tear down the open port at the precise moment the lease expires.
* **Auto-Healing:** If `firewalld` is restarted or reloaded, the daemon automatically re-establishes the D-Bus connection and restores active client states upon their next renewal heartbeat.
* **Security Hardened:** Includes protection against privileged port hijacking (e.g., SSH/HTTPS interception) and limits concurrent active rules per IP to prevent state exhaustion Denial of Service (DoS).

## Supported Operating Systems

* **Fully Supported:** Fedora, AlmaLinux, RHEL, CentOS Stream, Rocky Linux (Any system using `firewalld` natively).
* **Coming Soon:** Debian, Ubuntu, and derivatives.

## Installation

### Method 1: RPM via Fedora COPR (Recommended)
For RHEL, AlmaLinux, Fedora, and compatible derivatives, the daemon is packaged and maintained in COPR.

```bash
sudo dnf copr enable elitesalman/fw-natpmp
sudo dnf install fw-natpmp
sudo systemctl enable --now fw-natpmp
```

### Method 2: Compile From Source
You will need Go 1.18+ installed.

```bash
git clone [https://github.com/EliteSalman/fw-natpmp.git](https://github.com/EliteSalman/fw-natpmp.git)
cd fw-natpmp
go build -ldflags="-s -w" -o fw-natpmp main.go
sudo cp fw-natpmp /usr/sbin/
```

If compiling from source, deploy the systemd unit and configuration manually:

```bash
sudo mkdir -p /etc/fw-natpmp
sudo cp config.yaml /etc/fw-natpmp/
sudo cp fw-natpmp.service /usr/lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fw-natpmp
```

## Configuration

The configuration file is located at `/etc/fw-natpmp/config.yaml`. 

```yaml
# Interface to listen on for NAT-PMP requests (e.g., eth1, eth2)
# SECURITY WARNING: This MUST be a trusted internal interface.
listen_interface: "eth1"

# Port to listen on (Default: 5351)
listen_port: 5351

# The firewalld zone to apply dynamic rules to. 
# Leave blank ("") to auto-detect the default active zone.
firewall_zone: ""

# Maximum allowed lifetime for a port mapping in seconds.
max_lifetime: 86400

# Minimum allowed external port to prevent hijacking of privileged host services.
min_port: 1024

# Maximum concurrent port mappings allowed per client IP.
max_ports_per_client: 50
```

## Client Usage

Clients on the internal network (e.g., `192.0.2.x` range) can request port mappings using standard NAT-PMP software like qBittorrent, Tailscale, or CLI tools like `natpmpc`.

**Note:** The NAT-PMP protocol strictly dictates unicast UDP communication on port 5351. UPnP IGD clients relying on multicast discovery will not interact with this daemon.

Example manual request using `natpmpc` from a client machine:
```bash
# Request the public gateway IP
natpmpc -g 192.0.2.1

# Map external TCP port 8989 to internal port 8989
natpmpc -g 192.0.2.1 -a 8989 8989 tcp
```

## Licence
This project is licenced under the GNU General Public Licence v3 (GPLv3). See the `LICENSE` file for details.

# firewalld-natpmp

A lightweight, secure, and native NAT-PMP (RFC 6886) daemon designed exclusively for environments running `firewalld`. 

Unlike legacy UPnP or PCP daemons that interact directly with `iptables` or `nftables`—often leading to orphaned rules and hook conflicts—`firewalld-natpmp` communicates natively via the firewalld D-Bus API. It manages lease lifecycles entirely within its own memory space using zero-timeout permanent rules, preventing the routing micro-outages common during standard lease renewals. This ensures your firewall state remains clean and synchronised, making it an ideal solution for WireGuard VPN gateways and custom Linux routers.

## Features

* **Native D-Bus Integration:** Modifies firewall states safely using standard `firewalld` zone forwarding.
* **Strict RFC 6886 Compliance:** Fully supports dynamic ephemeral port allocation (`extPort == 0`) and protocol-wide mapping teardowns.
* **Zero Downtime Renewals:** Bypasses the D-Bus execution barrier for active lease renewals, eliminating network micro-outages caused by kernel netfilter rule recreation.
* **Firewalld Reload Resilience:** Automatically intercepts D-Bus `Reloaded` signals to instantly restore NAT leases into the runtime environment if an administrator reloads the firewall.
* **Crash Recovery & Namespace Isolation:** Tracks injected rules via an isolated JSON state file (`/var/run/firewalld-natpmp.json`). This ensures the daemon can recover gracefully from catastrophic crashes without ever touching or flushing external NAT rules manually added by administrators.
* **Graceful Teardowns:** Intercepts `SIGINT` and `SIGTERM` signals to proactively flush daemon-managed D-Bus port forwards before exiting, preventing orphaned rules.
* **DoS Protection:** Utilises a bounded worker pool to restrict concurrent UDP packet processing, preventing memory exhaustion attacks.
* **Subnet Filtering:** Optionally restrict port mapping requests to specific CIDR blocks (e.g., your local LAN or VPN tunnel interface).
* **Privileged Port Protection:** Blocks unauthorised attempts to hijack system ports (under 1024).
* **Zero Dependencies:** Written in Go, deployed as a single statically linked binary.

## Installation

### Fedora / CentOS Stream / RHEL / RHEL Clones (AlmaLinux, Rocky Linux, Oracle Linux) (via COPR)

You can install `firewalld-natpmp` directly from the official COPR repository:

```bash
sudo dnf copr enable elitesalman/firewalld-natpmp
sudo dnf install firewalld-natpmp
```

### Manual Build

Ensure you have Go 1.18+ installed. You can copy and paste the following block directly into your terminal to build and install the daemon, its configuration, and the systemd service.

```bash
git clone [https://github.com/EliteSalman/firewalld-natpmp.git](https://github.com/EliteSalman/firewalld-natpmp.git)
cd firewalld-natpmp
go build -buildmode=pie -ldflags="-s -w -extldflags '-static'" -o firewalld-natpmp main.go

# Install the binary, configuration, and systemd service file
sudo install -Dpm 0755 firewalld-natpmp /usr/sbin/firewalld-natpmp
sudo install -Dpm 0644 config.yaml /etc/firewalld-natpmp/config.yaml
sudo install -Dpm 0644 firewalld-natpmp.service /usr/lib/systemd/system/firewalld-natpmp.service

# Reload systemd to recognise the new service
sudo systemctl daemon-reload
```

## Configuration

Configuration is managed via `/etc/firewalld-natpmp/config.yaml`. Upon installation, you must edit this file to define your listening interface.

```yaml
# /etc/firewalld-natpmp/config.yaml
# Configuration file for the Firewalld NAT-PMP Daemon

# REQUIRED: The network interface the daemon listens on.
# You must uncomment and set this to match your environment (e.g., eth1, wg0).
# listen_interface: "eth1"

# The UDP port to listen for incoming NAT-PMP requests (RFC 6886 default is 5351)
listen_port: 5351

# The firewalld zone where port-forwarding rules will be dynamically applied.
# If left blank, the daemon automatically detects and uses the default active system zone.
firewall_zone: ""

# Maximum lease lifetime in seconds allowed for a port mapping (Default: 86400 / 24 hours)
max_lifetime: 86400

# Minimum external port allowed for client allocation to prevent privileged port hijacking (Default: 1024)
min_port: 1024

# Maximum number of active port mappings allowed per unique client IP address (Default: 50)
max_ports_per_client: 50

# Security: Restrict incoming requests to a specific subnet (e.g., your local LAN or VPN tunnel).
# Packets originating from outside this subnet will be dropped to prevent unauthorised WAN access.
# Uncomment and configure this to match your environment.
# allowed_subnet: "192.0.2.0/24"

# The external public WAN IP address returned to clients during Public IP queries.
# If left blank, the daemon falls back to auto-detecting the local outbound routing interface IP.
# Uncomment and configure this to match your environment if needed.
# public_ip: "203.0.113.1"

# Security: Maximum number of concurrent worker routines processing UDP packets to prevent memory exhaustion DoS floods (Default: 100)
worker_pool_size: 100
```

## Usage

Once configured, start and enable the daemon via systemd:

```bash
sudo systemctl enable --now firewalld-natpmp
```

To verify the daemon is successfully bound to your interface and D-Bus:

```bash
sudo systemctl status firewalld-natpmp
```

## Security Considerations

If you are deploying `firewalld-natpmp` in any environment (Home Router, VPC, or VPN Gateway):
1. Ensure `listen_interface` is set strictly to your internal network or tunnel interface (e.g., `eth1`, `wg0`). **Do not listen on your public WAN interface.**
2. Use the `allowed_subnet` variable to drop spoofed packets from unauthorised networks.
3. Explicitly define `public_ip` if your gateway sits behind another NAT layer (like an AWS/DigitalOcean VPC or CGNAT), otherwise clients will be given the internal routing address instead of your true public IPv4.

## Licence
This project is licenced under the GNU General Public Licence v3 (GPLv3). See the `LICENSE` file for details.

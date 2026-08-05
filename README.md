# colatrl

colatrl is an eBPF-based [CLAT](https://datatracker.ietf.org/doc/html/rfc6877) implementation for Linux, originally by [Maciej Żenczykowski](https://github.com/users/zenczykowski).

## Background

IPv4 addresses are exhausted. Networks — particularly mobile and enterprise networks — increasingly run IPv6-only infrastructure. However, many applications, servers, and services still require IPv4 to function. [RFC 6877](https://datatracker.ietf.org/doc/html/rfc6877) defines **464XLAT**, an architecture that restores IPv4 connectivity over IPv6-only networks without tunneling.

464XLAT uses two translators working in tandem:

- **CLAT** (Customer-side Translator) — runs on the host or CPE. Performs stateless 1:1 translation between a private IPv4 address and an IPv6 address, converting outbound IPv4 packets to IPv6 and inbound IPv6 packets back to IPv4.
- **PLAT** (Provider-side Translator) — runs in the network as a NAT64/DNS64 gateway. Performs stateful translation between the IPv6 traffic arriving from the CLAT and public IPv4 destinations on the internet.

The result is that IPv4-only applications on an IPv6-only host can reach IPv4 destinations transparently, with no tunneling overhead and no double-NAT for IPv6-native traffic.

colatrl implements the CLAT role using Linux `tc` BPF programs attached to the network interface. Packet translation happens in the kernel fast path — no userspace forwarding, no performance penalty.

## Requirements

- Linux kernel 5.10 or later
- An IPv6-only network with NAT64 and DNS64 service (the PLAT)
- x86_64 architecture (binary packages; other architectures must build from source)
- Root privileges
- Runtime dependencies: `bpftool`, `iproute2`, `ndisc6`, `bind9-host` (or `bind-utils`)

## Installation

### Quick install

```
curl -fsSL https://raw.githubusercontent.com/colatrl/colatrl/main/install.sh | sh
```

Detects your distribution, downloads the appropriate package from the [latest release](https://github.com/colatrl/colatrl/releases/latest), and prints the install command to run with `sudo`. Supported distributions: Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`). Other distributions receive build-from-source instructions.

> **x86_64 only.** Binary packages are built for x86_64. Other architectures must build from source.

### From PPA (Ubuntu)

```
sudo add-apt-repository ppa:anarkiwi/colatrl
sudo apt-get update
sudo apt-get install -y colatrl
```

### From release packages

Download the `.deb` or `.rpm` for your distro from the [latest release](https://github.com/colatrl/colatrl/releases/latest) and install it:

Debian/Ubuntu:
```
sudo apt-get install -y ./colatrl_*.deb
```

Fedora/RHEL:
```
sudo dnf install -y ./colatrl-*.rpm
```

### Build from source

```
sudo apt-get -y update && sudo apt-get install -y clang-19 g++ libc6-dev-i386
make
sudo make install
```

> **Note:** Source builds on distributions other than Debian/Ubuntu and Fedora/RHEL are untested and may require manual adjustment of build dependencies and compiler flags.

## Usage

### With systemd (recommended)

Install the service unit if it is not already present (package installs handle this automatically):

```
sudo cp debian/colatrl.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Enable and start:

```
sudo systemctl enable --now colatrl
```

Stop:

```
sudo systemctl stop colatrl
```

Check status:

```
sudo systemctl status colatrl
sudo journalctl -u colatrl -n 50
```

> **Note:** The service sets `net.ipv6.conf.all.forwarding=1` on start. This sysctl is not reverted when the service is stopped.

### Without systemd

Start:

```
sudo colatrl start
```

Stop:

```
sudo colatrl stop
```

Check current state:

```
sudo colatrl status
```

## Verifying operation

After a successful start, colatrl installs BPF programs on the network interface and adds an IPv4 default route. Verify with:

```
ip -4 route
```

You should see a route similar to:

```
default via inet6 fe80::... dev eth0 src 192.0.0.1 metric 1 mtu 1472
```

Test IPv4 connectivity:

```
ping -c 3 8.8.8.8
```

For a detailed view of the BPF maps and filter state:

```
sudo colatrl status
```

This prints the active BPF maps (interface MAC, source IP, ingress/egress translation rules) and tc filter configuration.

> **Note on startup output:** On kernels without BTF support, colatrl logs `libbpf: Error in bpf_create_map_xattr ... Retrying without BTF` during startup. This is expected and harmless — the BPF programs load correctly without BTF.

## License

[Apache 2.0](LICENSE)

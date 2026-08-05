# colatrl

colatrl is an experimental BPF based [CLAT](https://datatracker.ietf.org/doc/html/rfc6877) implementation, originally by [Maciej Żenczykowski](https://github.com/users/zenczykowski).

## installation

### quick install

```
curl -fsSL https://raw.githubusercontent.com/colatrl/colatrl/main/install.sh | sh
```

Detects your distribution, downloads the appropriate package from the [latest release](https://github.com/colatrl/colatrl/releases/latest), and prints the install command to run with `sudo`. Supported: Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`). Other distributions receive a source-build path — see the note below.

> **x86_64 only.** Binary packages are built for x86_64. Other architectures must build from source.

### from ppa (Ubuntu)

```
$ sudo add-apt-repository ppa:anarkiwi/colatrl
$ sudo apt-get update
$ sudo apt-get install -y colatrl
```

### from release packages

Download the `.deb` or `.rpm` for your distro from the [latest release](https://github.com/colatrl/colatrl/releases/latest) and install it:

Debian/Ubuntu:
```
$ sudo apt-get install -y ./colatrl_*.deb
```

Fedora/RHEL:
```
$ sudo dnf install -y ./colatrl-*.rpm
```

### local

```
$ sudo apt-get -y update && sudo apt-get install -y clang-19 g++ libc6-dev-i386
$ make
$ sudo make install
```

To install the [systemd service](debian/colatrl.service):

```
$ sudo cp debian/colatrl.service /etc/systemd/system/
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now colatrl
```

> **Note:** Source builds on distributions other than Debian/Ubuntu and Fedora/RHEL are untested and may require manual adjustment of build dependencies and compiler flags.
>
> **Note:** The service sets `net.ipv6.conf.all.forwarding=1` on start. This sysctl is not reverted when the service is stopped.

## usage without systemd

Start:

```
$ sudo colatrl start
Failed to find clat_errin_map
Failed to find clat_errout_map
Failed to find clat_ifmac_map
Failed to find clat_srcip_map
Failed to find clat_input_map
Failed to find clat_timer_map
Failed to find clat_output_map
Failed to read clat_output_map: BpfMap::readValue() failed: Bad file descriptor
PFX96[64:ff9b::] GW[fe80::21b:17ff:fe00:601] DEV[enp86s0] IFINDEX[2] SRC[2001:559:700d:8001:385d:6b0b:d56d:7be5] MTU6[1500] MTU4[1472] MAC[88:ae:dd:72:1a:c6] LOCAL4[192.0.0.1] PROXY[] HINT[]
CLATIP[2001:559:700d:8001:a6bb:dbd5:b4de:7328] PREEXIST[false]
libbpf: Error in bpf_create_map_xattr(clat_errin_map):Invalid argument(-22). Retrying without BTF.
libbpf: Error in bpf_create_map_xattr(clat_errout_map):Invalid argument(-22). Retrying without BTF.
libbpf: Error in bpf_create_map_xattr(clat_errin_map):Invalid argument(-22). Retrying without BTF.
libbpf: Error in bpf_create_map_xattr(clat_errout_map):Invalid argument(-22). Retrying without BTF.
Install on dev[2/enp86s0] mac[88:ae:dd:72:1a:c6] mtu4[1472] ip4[192.0.0.1] ip6[2001:559:700d:8001:a6bb:dbd5:b4de:7328] pfx96[64:ff9b::/96]

clat_errin_map<ClatErrorKey,u64>:
  INGRESS_IGN_NOT_CLAT -> 3

clat_errout_map<ClatErrorKey,u64>:

clat_ifmac_map<IfIndex,MacAddress>:
  2 (enp86s0) -> 88:ae:dd:72:1a:c6

clat_srcip_map<ClatSrcIpKey,ClatSrcIpValue>:
  {ifindex: 2 (enp86s0), local6: 2001:559:700d:8001:a6bb:dbd5:b4de:7328} -> {pfx96: 64:ff9b::/96, local4: 192.0.0.1}

clat_input_map<ClatIngress6Key,ClatIngress6Value>:
  {iif: 2 (enp86s0), pfx96: 64:ff9b::/96, local6: 2001:559:700d:8001:a6bb:dbd5:b4de:7328} -> {oif: 2 (enp86s0), local4: 192.0.0.1, packets: 0, bytes:0}

clat_timer_map<u32,ClatTimerValue>:
  0 -> {count: 0, last_time: 0}

clat_output_map<ClatEgress4Key,ClatEgress4Value>:
  {iif: 2 (enp86s0), local4: 192.0.0.1} -> {oif: 2 (enp86s0), local6: 2001:559:700d:8001:a6bb:dbd5:b4de:7328, pfx96: 64:ff9b::/96, oifIsEthernet: true, pmtu: 1472, packets: 0, bytes:0}

Triggering DAD for 2001:559:700d:8001:a6bb:dbd5:b4de:7328/128 on enp86s0
Soliciting fe80::21b:17ff:fe00:601 (fe80::21b:17ff:fe00:601) on enp86s0...
Target link-layer address: 00:1B:17:00:06:01
 from fe80::21b:17ff:fe00:601
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=112 time=8.12 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=112 time=9.38 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=112 time=8.54 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 8.116/8.676/9.375/0.523 ms
$ ip -4 route
default via inet6 fe80::21b:17ff:fe00:601 dev enp86s0 src 192.0.0.1 metric 1 mtu 1472 
default dev clat scope link metric 2048 mtu 1260 advmss 1220 
```

Stop:

```
$ sudo colatrl stop
```

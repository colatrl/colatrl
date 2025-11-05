# colatrl

colatrl is an experimental BPF based [CLAT](https://datatracker.ietf.org/doc/html/rfc6877) implementation, originally by [Maciej Żenczykowski](https://github.com/users/zenczykowski).

## implementation plans

* Packaging for Debian/Ubuntu
* [RFC 6052](https://datatracker.ietf.org/doc/html/rfc6052)/[RFC 8215](https://datatracker.ietf.org/doc/html/rfc8215) support

## experimental usage

Build:

```
$ ./scripts/build.sh
```

Install:

```
$ sudo ./scripts/install.sh 
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

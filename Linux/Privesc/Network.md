---
id: Network
aliases: []
tags:
  - Linux/Privesc/Network
links: "[[Privesc]]"
---

# Network

___

<!-- Network Information {{{-->
## Network Information

Gather Network Information

<!-- Tip {{{-->
> [!tip]
>
> - Subnet
> - [NIC](https://en.wikipedia.org/wiki/Network_interface_controller)
>   names
> - Additional [NIC](https://en.wikipedia.org/wiki/Network_interface_controller)s
<!-- }}} -->

[ip](https://linux.die.net/man/8/ip) —
Show / manipulate routing, devices, policy routing and tunnels

```sh
ip a
```

```sh
ip addr
```

[ifconfig](https://linux.die.net/man/8/ifconfig) —
Configure a network interface

```sh
ifconfig
```

___
<!-- }}} -->

<!-- ARP Cache {{{-->
## ARP Cache

Enumerate the [[ARP]] cache to discover network neighbors

<!-- Tip {{{-->
> [!tip]
>
> - Live hosts communicating on the LAN
> - Cross-reference hosts with discovered [[SSH Keys]]
> - Local gateway MAC address
> - ARP spoofing anomalies
> - Indicators of MITM attacks
<!-- }}} -->

[ip](https://linux.die.net/man/8/ip) —
[[ARP]] table

```sh
ip neigh || route
```

[ip](https://linux.die.net/man/8/ip) —
[[ARP]] table for a specific interface

```sh
ip neigh show dev eth0
```

Kernel [[ARP]] table

```sh
cat /proc/net/arp
```

Old method

```sh
(arp -e || arp -a)
```

___
<!-- }}} -->

<!-- DNS {{{-->
## DNS

Enumerate configured DNS services

<!-- Tip {{{-->
> [!tip]
>
> Check if the host is configured to use internal DNS
> to query the Active Directory environment
<!-- }}} -->

[Resolv.conf](https://en.wikipedia.org/wiki/Resolv.conf) —
Configure the system's Domain Name System (DNS) resolver

```sh
cat /etc/resolv.conf
```

[dnsdomainname](https://linux.die.net/man/1/dnsdomainname) —
Show the system's DNS domain name

```sh
dnsdomainname
```
___
<!-- }}} -->

<!-- Files {{{-->
## Files

Enumerate files used by network services

```sh
lsof -i
```
___
<!-- }}} -->

<!-- Hosts {{{-->
## Hosts

Enumerate the [hosts](https://en.wikipedia.org/wiki/Hosts_(file)) file

```sh
cat /etc/hosts
```

___
<!-- }}} -->

<!-- Hostname {{{-->
## Hostname

[hostname](https://linux.die.net/man/1/hostname) —
Show or set the system's host name

```sh
hostname
```

```sh
cat /etc/hostname
```

___
<!-- }}} -->

<!-- Internet Service Daemon {{{-->
## Internet Service Daemon

[inetd](https://en.wikipedia.org/wiki/Inetd) &
[xinetd](https://en.wikipedia.org/wiki/Xinetd)
are daemons that manage Internet-based connectivity

```sh
cat /etc/inetd.conf /etc/xinetd.conf
```
___
<!-- }}} -->

<!-- Interfaces {{{-->
## Interfaces

Enumerate network interfaces

```sh
cat /etc/networks
```
___
<!-- }}} -->

<!-- Iptables {{{-->
## Iptables

Enumerate [Iptables](https://en.wikipedia.org/wiki/Iptables) rules

[iptables](https://linux.die.net/man/8/iptables) —
Administration tool for IPv4 packet filtering and NAT

```sh
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)
```

___
<!-- }}} -->

<!-- Open Ports {{{-->
## Open Ports

Enumerate open ports

```sh
(netstat -punta || ss --ntpu)
```

```sh
(netstat -punta || ss --ntpu) | grep "127.0"
```

___
<!-- }}} -->

<!-- Routing Table {{{-->
## Routing Table

Enumerate the routing table

<!-- Tip {{{-->
> [!tip]
>
> Find available networks
>
<!-- }}} -->

[route](https://linux.die.net/man/8/route) —
Show / manipulate the IP routing table

```sh
route
```

[netstat](https://linux.die.net/man/8/netstat) —
Print network connections, routing tables, interface statistics,
masquerade connections, and multicast memberships

```
netstat -rn
```
___
<!-- }}} -->

<!-- Sniffing {{{-->
## Sniffing

Check sniffing traffic is possible

[tcpdump](https://linux.die.net/man/8/tcpdump) —
Dump traffic on a network

```sh
timeout 1 tcpdump
```

___
<!-- }}} -->

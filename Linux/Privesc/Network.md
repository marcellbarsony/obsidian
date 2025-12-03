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

Gather Netowrk Information

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

Enumerate the [[ARP]] cache

<!-- Tip {{{-->
> [!tip]
>
> - Live hosts communicating on the LAN
> - Cross-reference hosts with discovered [[SSH Keys]]
> - Local gateway MAC address
> - ARP spoofing anomalies
> - Indicators of MITM attacks
<!-- }}} -->

[[ARP]] table

```sh
ip neigh
```

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
arp -a
```

___
<!-- }}} -->

<!-- Hosts {{{-->
## Hosts

Check the [hosts](https://en.wikipedia.org/wiki/Hosts_(file)) file

```sh
cat /etc/hosts
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

<!-- Resolv.conf {{{-->
## Resolv.conf

[Resolv.conf](https://en.wikipedia.org/wiki/Resolv.conf) —
Configure the system's Domain Name System (DNS) resolver

<!-- Tip {{{-->
> [!tip]
>
> Check if the host is configured to use internal DNS
> to query the Active Directory environment
<!-- }}} -->

```sh
cat /etc/resolv.conf
```

___
<!-- }}} -->

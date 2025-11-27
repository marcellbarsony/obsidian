---
id: Network
aliases: []
tags:
  - Linux/Privesc/Network
links: "[[Privesc]]"
---

# Network

___

<!-- ARP Cache {{{-->
## ARP Cache

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

<!-- Tip {{{-->
> [!tip]-
>
> Checking the ARP table can reveal:
> - Local gateway MAC address
> - Live hosts communicating on the LAN
> - ARP spoofing anomalies
> - Indicators of MITM attacks
<!-- }}} -->
___
<!-- }}} -->

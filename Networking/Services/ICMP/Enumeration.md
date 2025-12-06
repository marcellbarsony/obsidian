---
id: Enumeration
aliases: []
tags:
  - Networking/Services/ICMP/Enumeration
---

# Enumeration

<!-- ICMP Echo Requests {{{-->
## ICMP Echo Requests

Enumerating live hosts on a network can be done using ICMP Echo Requests:

```sh
ping -c 1 <network_range>
```

___

<!-- }}} -->

<!-- ICMP Time Exceeded Messages {{{-->
## ICMP Time Exceeded Messages

Trace the route packets take to a destination and identify routers along the
path

```sh
traceroute $target
```

___

<!-- }}} -->

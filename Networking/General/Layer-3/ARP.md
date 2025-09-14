---
id: ARP
aliases:
  - Address Resolution Protocol
tags:
  - Networking/General/Layer-3/ARP
links: "[[Layer-3]]"
---

# Address Resolution Protocol (ARP)

**Address Resolution Protocol** (**ARP**) is a stateless network protocol used
to resolve a network layer (*Layer 3*) IP address to a data link layer
(*Layer 2*) MAC address by mapping a host's IP address to its corresponding MAC
address.

```sh
1   10.129.12.100 -> 10.129.12.255 ARP 60  Who has 10.129.12.101?  Tell 10.129.12.100
2   10.129.12.101 -> 10.129.12.100 ARP 60  10.129.12.101 is at AA:AA:AA:AA:AA:AA

3   10.129.12.102 -> 10.129.12.255 ARP 60  Who has 10.129.12.103?  Tell 10.129.12.102
4   10.129.12.103 -> 10.129.12.102 ARP 60  10.129.12.103 is at BB:BB:BB:BB:BB:BB
```

## ARP Request

The **ARP Request** is a broadcast to all devices on the LAN to resolve the IP
address of the destination device to its MAC address.

## ARP Reply

The **ARP Reply** is contains the IP and the MAC addresses of both the
requesting and responding hosts.

## Attack Vectors

[ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) (*aka* `ARP cache
poisoning` *or* `ARP poison routing`) is a technique by which an attacker sends
spoofed ARP messages over a LAN.

### Tools

- [GitHub - Ettercap](https://github.com/Ettercap/ettercap)
- [GitHub - Cain](https://github.com/xchwarze/Cain)

---
id: MAC-address
aliases: []
tags:
  - Networking/Layer2/MAC
links: "[[Layer-2]]"
---

# MAC Address

**MAC address** is a 48-bit (6 byte) unique identifier (physical address,
Layer 2) of a network interface.

Example: `8c:3b:4a:b4:95:4b`

- The first 3 octets (24 bits) is the `Organization Unique Identifier (OUI)`
- The last 3 octets (24 bits) is the `Network Interface Controller (NIC)` or
`Individual Address Part`

The last 2 bits in the first octet identifies if a MAC address is **Unicast**
(**0**) or **Multicast** (**1**).

If the target is on the **same subnet**, the message is delivered to their
physical address.

If the target is on a **different subnet**, the Ethernet frame is addressed to
the MAC address of the responsible router (default gateway).

**Address Resolution Protocol** (**ARP**) is used to associate MAC with IPv4
Addresses.

## MAC Unicast

Unicast is a **one-to-one communication** where the packet is sent from one
source MAC address to one specific destination MAC address on the local
network.

## MAC Multicast

Multicast is a **one-to-many communication** where the packet is sent from one
source MAC address to a group of specific destination MAC addresses that are
part of a multicast group.

## MAC Broadcast

Broadcast is a **one-to-all communication**  where the packet is sent from one
source MAC address to all devices on the local network using the broadcast MAC
address (**FF:FF:FF:FF:FF:FF**).

It is used when the sender doesn’t know the recipient’s MAC address.

## Attack Vectors

There are several attack vectors that can potentially be exploited through the
use of MAC addresses:

- **MAC spoofing**: The attacker is changing the MAC address to impersonate
  another device on a LAN.

- **MAC flooding**: The attacker sends a large number of fake MAC addresses to a
  network switch, causing the switch's MAC address table to overflow.

- **MAC address filtering**: Networks may be configured to allow access to a
  resources with specific MAC addresses.

## Reserved Addresses

Local Ranges

- 0**2**:00:00:00:00:00
- 0**6**:00:00:00:00:00
- 0**A**:00:00:00:00:00
- 0**E**:00:00:00:00:00

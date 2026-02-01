---
id: IPv6
aliases:
  - Internet Protocol v6
tags:
  - Networking/General/Layer-3/IPv6
links: "[[Networking/General/Layer-3/General]]"
---

# IPv6 Addresses

**IPv6** is a 128-bit (16 bytes) long Internet Protocol address system that
provides a larger address space, supports auto-configuration, and enhances
security with built-in IPsec encryption.

**IPv6** follows the `end-to-end` principle and provides publicly accessible IP
addresses for every end device without the need for NAT.

___

<!-- IPv6 Features {{{-->
## IPv6 Features

**IPv6** features:

- Larger address space (*~ 340 undecillion*)
- Address self-configuration (*SLAAC*)
- Multiple IPv6 addresses per interface
- Faster routing
- End-to-end encryption (*IPsec*)
- Data packages up to 4 GByte

___
<!-- }}} -->

<!-- IPv6 Types {{{-->
## IPv6 Types

**IPv6** types:

| Type | Description |
| --- | --- |
| Unicast | Addresses for a single interface. |
| Anycast | Addresses for multiple interfaces, where only one of them receives the packet. |
| Multicast | Addresses for multiple interfaces, where all receive the same packet. |

___
<!-- }}} -->

<!-- IPv6 Address {{{-->
## IPv6 Address

### Notation

An IPv6 address can look like the following

- Full: `fe80:0000:0000:0000:dd80:b1a9:6687:2d3b/64`
- Short: `fe80::dd80:b1a9:6687:2d3b/64`

In [RFC 5952](https://datatracker.ietf.org/doc/html/rfc5952), the aforementioned
IPv6 address notation was defined:

- All alphabetical characters are always written in lower case
- All leading zeros of a block are always omitted
- One or more consecutive blocks of 4 zeros (hex) are shortened by two colons
  (`::`)
- The shortening to two colons (`::`) may only be performed once starting from
  the left

### Address parts

An IPv6 address consists of two parts:

- **Network Prefix** (*network part*): Identifies the network, subnet, or
  address range
- **Interface Identifier** (*host part*): Formed from the 48-bit MAC address and
  is converted to a 64-bit address.

___
<!-- }}} -->

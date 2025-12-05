---
id: General
aliases: []
tags:
  - Networking/Services/ISAKMP/General
ports:
    - udp/500
    - udp/4500
---

# General

**Internet Security Association and Key Management Protocol**
(*[ISAKMP](https://en.wikipedia.org/wiki/Internet_Security_Association_and_Key_Management_Protocol)*)
is the protocol
(*[RFC 2408](https://datatracker.ietf.org/doc/html/rfc2408)*)
used to establish security associations
(*[SA](https://en.wikipedia.org/wiki/Security_association)*)
and cryptographic keys in an Internet environment

It operates on UDP port `500` and uses two main modes:

- **Main Mode**: Exchanges information in encrypted form (*secure*)
- **Aggressive Mode**: Exchanges identity information in cleartext
  (*faster but less secure*)

**Internet Key Exchange**
(*[IKE](https://en.wikipedia.org/wiki/Internet_Key_Exchange)*)
(*vesioned `IKEv2` and `IKEv2`*)
is the protocol used to set up security associations
(*[SA](https://en.wikipedia.org/wiki/Security_association)*)
in the in [IPsec](https://en.wikipedia.org/wiki/IPsec)
protocol suite (*e.g, VPN connections*)

___

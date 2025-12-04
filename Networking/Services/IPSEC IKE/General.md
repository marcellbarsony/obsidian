---
id: General
aliases: []
tags:
  - Networking/Services/IPSEC-IKE/General
ports:
    - udp/500
    - udp/4500
---

# General

IKE ([Internet Key Exchange](https://en.wikipedia.org/wiki/Internet_Key_Exchange))
is the protocol used to set up [security associations](https://en.wikipedia.org/wiki/Security_association)
(SA) in [IPsec](https://en.wikipedia.org/wiki/IPsec) VPN connections

It operates on UDP port `500` and uses two main modes:

- **Main Mode**: Exchanges information in encrypted form (*secure*)
- **Aggressive Mode**: Exchanges identity information in cleartext
  (*faster but less secure*)

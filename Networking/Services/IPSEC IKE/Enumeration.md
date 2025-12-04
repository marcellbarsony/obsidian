---
id: Enumeration
aliases: []
tags:
  - Networking/Services/IPSEC-IKE/Enumeration
---

# Enumeration

<!-- Fingerprinting {{{-->
## Fingerprinting

[ike-scan](https://linux.die.net/man/1/ike-scan) —
Discover and fingerprint IKE hosts (*IPsec VPN servers*)

Extract the hash or preshared key

```sh
ike-scan --aggressive <target>
```

Extract information (*e.g., hashing format, encryption algorithms*)

```sh
ike-scan -M <target>
```

___
<!-- }}} -->

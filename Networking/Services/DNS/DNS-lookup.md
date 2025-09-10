---
id: dns-lookup
aliases:
  - DNS Lookup
tags:
  - Networking/Services/DNS
links: "[[DNS]]"
resources:
  - https://dnsdumpster.com/
---

# DNS lookup

Resolve a given hostname to the corresponding IP.

```sh
nslookup <target_domain>
```

## Reverse DNS lookup

Reverse DNS lookup

```sh
nslookup -type=PTR <target_ip>
```

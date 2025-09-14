---
id: dns-lookup
aliases:
  - DNS Lookup
tags:
  - Networking/Services/DNS/DNS-Lookup
links: "[[DNS]]"
---

# DNS Lookup

- [DNSDumpster](https://dnsdumpster.com/)

## DNS Lookup

Resolve a given hostname to the corresponding IP.

```sh
nslookup <target_domain>
```

## Reverse DNS lookup

Reverse DNS lookup

```sh
nslookup -type=PTR <target_ip>
```

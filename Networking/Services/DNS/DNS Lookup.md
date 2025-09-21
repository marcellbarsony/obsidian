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

Resolve a **domain name** to the corresponding **IP address**.

```sh
nslookup <target_domain>
```

## Reverse DNS Lookup

Resolve an **IP address** to the corresponding **domain name**.

```sh
nslookup -type=PTR <target_ip>
```

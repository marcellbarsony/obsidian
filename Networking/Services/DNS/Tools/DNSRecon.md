---
id: DNSRecon
aliases: []
tags:
  - Networking/Services/DNS/Tools/DNSRecon
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# DNSRecon

[DNSRecon](https://github.com/darkoperator/dnsrecon)
is a DNS Enumeration Script

## Usage

General enumeration

```sh
dnsrecon -d "<target_domain>"
```

Standard enumeration and
[[DNS/Enumeration#AXFR Zone Transfer|AXFR Zone Transfer]]

```sh
dnsrecon -a -d "<target_domain>"
```

DNS bruteforcing/dictionary attack

```sh
dnsrecon -t brt -d "<target_domain>" -n "<nameserver.com>" -D "<wordlist.txt>"
```

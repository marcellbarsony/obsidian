---
id: Enumeration
aliases: []
tags: []
---

# Enumeration


## Nmap

Nmap scan using the Nmap `ipmi-version` [[Nmap Scripting Engine|NSE]] script to
footprint the service

```sh
sudo nmap -sU --script ipmi-version -p 623 <target_domain>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
> ```
> ```sh
> Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 21:48 GMT
> Nmap scan report for ilo.inlanfreight.local (172.16.2.2)
> Host is up (0.00064s latency).
>
> PORT    STATE SERVICE
> 623/udp open  asf-rmcp
> | ipmi-version:
> |   Version:
> |     IPMI-2.0
> |   UserAuth:
> |   PassAuth: auth_user, non_null_user
> |_  Level: 2.0
> MAC Address: 14:03:DC:674:18:6A (Hewlett Packard Enterprise)
>
> Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
> ```
<!-- }}} -->

## Metasploit

### Version Scan

### Dumping Hashes

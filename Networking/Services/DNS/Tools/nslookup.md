---
id: dig
tags:
  - Networking/Services/DNS/Tools/nslookup
links: "[[Services]]"
---

# nslookup

> [!warning]
>
> Deprecated

> [!todo]

## Usage

Ask the DNS server `10.129.14.128` for the NS records for the
domain `inlanefreight.htb`

```sh
nslookup -type=NS <target_domain> [dns_ip]
```

> [!example]-
>
> ```sh
> nslookup -type=NS inlanefreight.htb 10.129.14.128
> ```

Resolve a **domain name** to the corresponding **IP address**

```sh
nslookup <target_domain>
```

Resolve an **IP address** to the corresponding **domain name**
(*reverse lookup*)

```sh
nslookup -type=PTR $target
```

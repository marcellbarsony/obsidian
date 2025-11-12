---
id: Domain Information
aliases: []
tags:
  - Networking/Enumeration/Infrastructure/Domain-Information
---

# Domain Information

<!-- 3rd Party Sites {{{-->
## 3rd Party Sites

<!-- Domain.Glass Results {{{-->
### Domain.Glass

[domain.glass](https://domain.glass) — Transparent Domain Information

<!-- }}} -->

___
<!-- }}} -->

<!-- Subdomain Discovery {{{-->
## Subdomain Discovery

<!-- SSL Certificate {{{-->
### SSL Certificate

Get SSL Certificate

```sh
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```

Get SSL Certificate & Filter by unique subdomains

```sh
curl -s https://crt.sh/\?q\=<example.com>\&output\=json | \
    jq . | \
    grep name | \
    cut -d":" -f2 | \
    grep -v "CN=" | \
    cut -d'"' -f2 | \
    awk '{gsub(/\\n/,"\n");}1;' | \
    sort -ucurl -s https://crt.sh/\?q\=<example.com>\&output\=json | \
    jq . | \
    grep name | \
    cut -d":" -f2 | \
    grep -v "CN=" | \
    cut -d'"' -f2 | \
    awk '{gsub(/\\n/,"\n");}1;' | \
    sort -u
```

Identify hosts directly accessible from the Internet

```sh
for i in $(cat subdomainlist); do \
    host $i | \
    grep "has address" | \
    grep <example.com> | \
    cut -d" " -f1,4; \
done
```
<!-- }}} -->

<!-- Shodan {{{-->
### Shodan

The hosts then can be investigated further with
[Shodan](https://www.shodan.io/), that finds devices and systems connected to
the Internet: it searches for open TCP/IP ports, filters the systems
to specific criteria, and finds devices and systems (*e.g., IoT*).

```sh
for i in $(cat subdomainlist); do \
    host $i | \
    grep "has address" | \
    grep inlanefreight.com | \
    cut -d" " -f4 >> ip-addresses.txt; \
done
```

```sh
for i in $(cat ip-addresses.txt); do \
    shodan host $i; \
done
```
<!-- }}} -->

___
<!-- }}} -->

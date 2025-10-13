---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SMTP/Enumeration
links: "[[Networking/Services/SMTP/General|SMTP]]"
---

# Enumeration

- [Hacktricks - SMTP/s](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html)

<!-- Banner Grabbing {{{-->
## Banner Grabbing

### SMTP

#### Netcat

Get banner with [[netcat]]

```sh
nc -vn <target_ip> 25
```

Get banner with [[netcat]] `EHLO`

```sh
echo "EHLO test" | nc target.com 25
```

#### Telnet

Get banner with [[Telnet/General|Telnet]]

```sh
telnet <target_ip> 25
```

### SMTPS

SSL/TLS with `starttls` command

```sh
openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587
```

SSL/TLS without `starttls` command

```sh
openssl s_client -crlf -connect smtp.mailgun.org:465
```

<!-- }}} -->

<!-- Nmap {{{-->
## Nmap

Detect services and identify server capabilities

```sh
nmap -p 25,465,587 <target_ip>
```

Scan port `25` using the default scripts

```sh
sudo nmap -sC -sV <target_ip> -p25
```

Use the `EHLO` command to list all possible commands that can be executed on the
**SMTP Server**

```sh
nmap -p25 --script smtp-commands <target_ip>
```

<!-- }}} -->

<!-- Open Relay {{{-->
### Open Relay

Identify the target **SMTP Server** as an open relay, using 16 different tests,
using the [smtp-open-relay](https://nmap.org/nsedoc/scripts/smtp-open-relay.html)
NSE script

```sh
nmap -p25 --script smtp-open-relay <target_ip> -v
```

<!-- }}} -->

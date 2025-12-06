---
id: Enumeration
aliases: []
tags:
  - Networking/Services/Telnet/Enumeration
---

# Enumeration

___

<!-- Service {{{-->
## Service

[[Nmap]] — Identify Telnet server

```sh
nmap $target -p 23 -oA telnet-identify
```

[[Nmap]] — Assess encryption on Telnet server

```sh
nmap $target -p 23 --script telnet-encrpytion -oA telnet-script-encryption
```
___
<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

[[Netcat]]

```sh
ncat -nv $target 23
```

[[Telnet/General|Telnet]]

```sh
telnet $target 23
```

[Shodan-cli](https://help.shodan.io/)

```sh
shodan stream --ports 23,1023,2323 --datadir telnet-data/ --limit 10000
```

[[Nmap]]

```sh
nmap -sCV $target -p 23 --script "*telnet* and safe" -oA telnet-banner-grabbing
```

[[Metasploit]] — Telnet Login Check Scanner
(*[telnet_version](https://www.rapid7.com/db/modules/auxiliary/scanner/telnet/telnet_login/)*)

```sh
use auxiliary/scanner/telnet/telnet_version
```

<!-- Example {{{-->
> [!example]-
>
> This module will test a telnet login on a range of machines
> and report successful logins
>
> ```sh
> msfconsole
> ```
> ```sh
> msf > use auxiliary/scanner/telnet/telnet_version
> ```
> ```sh
> msf > set rhosts $TARGET_IP
> ```
> ```sh
> msf > set rport $TARGET_PORT
> ```
> ```sh
> msf > set threads 5
> ```
> ```sh
> msf > exploit
> ```
<!-- }}} -->

___
<!-- }}} -->

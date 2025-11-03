---
id: Enumeration
aliases: []
tags:
  - Networking/Services/Telnet/Enumeration
---

# Enumeration

___

<!-- Banner Grabbing {{{-->
## Banner Grabbing

[[Netcat]]

```sh
ncat -nv <target_ip> <target_port>
```

[[Telnet/General|Telnet]]

```sh
telnet <target_ip> <target_port>
```

[Shodan-cli](https://help.shodan.io/)

```sh
shodan stream --ports 23,1023,2323 --datadir telnet-data/ --limit 10000
```

[[Nmap]]

```sh
nmap -sCV -p <target_port> --script "*telnet* and safe" <target_ip> -oA telnet-banner-grabbing
```

[[Metasploit]] — Telnet Login Check Scanner
(*[telnet_version](https://www.rapid7.com/db/modules/auxiliary/scanner/telnet/telnet_login/)*)

```sh
msf > use auxiliary/scanner/telnet/telnet_version
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



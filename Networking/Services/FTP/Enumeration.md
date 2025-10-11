---
id: Enumeration
aliases: []
tags:
  - Networking/Services/FTP/Enumeration
links: "[[FTP]]"
---

# Enumeration

<!-- Checklist {{{-->
## Checklist

- [ ] [[Enumeration#Nmap|Nmap scan]]
- [ ] [[Enumeration#Banner Grabbing|Banner grabbing]]
    - [ ] [[netcat]]
    - [ ] [[Networking/Services/Telnet/General#Usage|Telnet]]
- [ ] [[Enumeration#Certificate|TLS certificate enumeration]]
- [ ] [[Enumeration#Default and Common Directories|Common default directories]]

<!-- }}} -->

<!-- Nmap {{{-->
## Nmap

Launch the default FTP script scan (*Unauthenticated Enumeration*)

```sh
sudo nmap -sC -sV -p21 -A <target_ip> --script-trace
```

<!-- Info {{{-->

> [!info]-
>
> - `-sC`: Default script scan
> - `-sV`: Version scan
> - `-A`: Aggressive scan
> - `--script-trace`: Trace the progress of the NSE script (*optional*)
<!-- }}} -->

<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

Grab the FTP banner with [[netcat]]

```sh
nc -nv <target_ip> 21
```

Grab the FTP banner with [[Networking/Services/Telnet/General|Telnet]]

```sh
telnet <target_ip> 21
```
<!-- }}} -->

<!-- Certificate {{{-->
## Certificate

Update the connection to TLS, display the server's:

- TLS certificate (e.g., *hostname*, *e-mail*)
- connection details

```sh
openssl s_client -connect <target_ip>:21 -starttls ftp
```

```sh
openssl s_client -connect crossfit.htb:21 -starttls ftp
```
<!-- }}} -->

<!-- Default and Common Directories {{{-->
## Default and Common Directories

FTP servers can have default or common directories
that may contain sensitive information

```sh
gobuster dir -u ftp://<ip> -w <wordlist.txt>
```
<!-- }}} -->

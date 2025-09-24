---
id: Enumeration
aliases: []
tags:
  - Networking/Services/FTP/Enumeration
links: "[[FTP]]"
---

# FTP Enumeration

## Nmap Scripts

Launch the default FTP script scan (Unauthenticated Enumeration)

```sh
sudo nmap -sC -sV -p21 -A <target_ip> --script-trace
```

- `-sC`: Default script scan
- `-sV`: Version scan
- `-A`: Aggressive scan
- `--script-trace`: Trace the progress of the NSE script (*optional*)

## Banner Grabbing

Grab the FTP banner with netcat

```sh
nc -nv <target_ip> 21
```

Grab the FTP banner with telnet

```sh
telnet <target_ip> 21
```

## Certificate

Update the connection to TLS, display the server's:

- TLS certificate (e.g., hostname, e-mail)
- connection details

```sh
openssl s_client -connect <target_ip>:21 -starttls ftp
```

## Default and Common Directories

FTP servers can have default or common directories that may contain sensitive
information

```sh
gobuster dir -u ftp://<ip> -w <wordlist.txt>
```

---
id: Enumeration
aliases: []
tags:
  - FTP
links: "[[FTP]]"
---

# FTP Enumeration

## Banner grabbing

```sh
nc -vn <ip> 21
```

## Certificate

```sh
openssl s_client -connect <ip>:21 -starttls ftp
```

## Unauthenticated enumeration

FTP Unauth Enum gathers information without logging in with valid credentials

```sh
sudo nmap -sV -p21 -sC -A <ip>
```

## Default and common directories

FTP servers may have default or common directories that may contain sensitive
information.

```sh
gobuster dir -u ftp://<ip> -w <wordlist>
```

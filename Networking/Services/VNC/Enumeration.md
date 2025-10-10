---
id: Enumeration
aliases: []
tags:
  - Networking/Services/ICMP/General
---

# Enumeration


## Nmap

```sh
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p <target_port> <target_ip>
```

## Metasploit

```sh
msf> use auxiliary/scanner/vnc/vnc_none_auth
```

## Decrypting VNC Password

The default password is stored in `~/.vnc/passwd`

If the password looks encrypted, it is probably ciphered with
[3des](https://en.wikipedia.org/wiki/Triple_DES)

The password may be decrypted with
[vncpwd](https://github.com/jeroennijhof/vncpwd)

```sh
vncpwd <vnc_password_file>
```

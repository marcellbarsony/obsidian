---
id: Enumeration
aliases: []
tags:
  - Networking/Services/VNC/Enumeration
---

# Enumeration

<!-- Service {{{-->
## Service

```sh
nmap -p 5900-5906 <target> -oA vnc-detect
```

```sh
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p <target_port> <target_ip> -oA vnc-script-all
```

___
<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

[[Netcat]] — Grab Service Banner

```sh
nc -vn <target> 5900
```

[[Netcat]] — Get VNC handshake

```sh
echo "" | nc <target> 5900
```
<!-- }}} -->

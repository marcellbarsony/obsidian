---
id: Enumeration
aliases: []
tags:
  - Networking/Services/VNC/Enumeration
---

# Enumeration

___

<!-- Service {{{-->
## Service

Enumerate VNC service

[[Nmap]] — Detect VNC Service

```sh
nmap $target -p 5900-5906 -oA vnc-service-detect
```

[[Nmap]] — Run default VNC enumeration scripts

```sh
nmap -sV $target -p <port> --script vnc-info,realvnc-auth-bypass,vnc-title -oA vnc-script-all
```

<!-- Banner {{{-->
### Banner

Grab VNC service banner

[[Netcat]] — Grab Service Banner

```sh
nc -vn $target 5900
```

[[Netcat]] — Get VNC handshake

```sh
echo "" | nc $target 5900
```

<!-- }}} -->

___
<!-- }}} -->

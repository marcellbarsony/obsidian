---
id: Enumeration
aliases: []
tags:
  - Networking/Services/VNC/Enumeration
---

# Enumeration

<!-- Service {{{-->
## Service

Detect [[VNC/General|VNC]] Service

```sh
nmap $target -p 5900-5906 -oA vnc-detect
```

```sh
nmap -sV $target -p <port> --script vnc-info,realvnc-auth-bypass,vnc-title -oA vnc-script-all
```

<!-- Banner {{{-->
### Banner

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

---
id: Usage
aliases: []
tags:
  - Networking/Services/RDP/Usage
links:
  [[Services]]
---

# Usage

___

<!-- Linux {{{-->
## Linux

<!-- xfreerdp {{{-->
### xfreerdp

[xfreerdp](https://linux.die.net/man/1/xfreerdp) —
FreeRDP X11 client

<!-- Install {{{-->
#### Install

Install

```sh
sudo apt install freerdp3-x11
```
<!-- }}} -->

<!-- Connect {{{-->
#### Connect

Basic connection

```sh
xfreerdp /v:$target
```

With credentials

```sh
xfreerdp /u:<username> /p:<password> /v:$target
```

With domain

```sh
xfreerdp /u:<DOMAIN>\\ /p:<password> /v:$target
```

Full options

```sh
xfreerdp /u:<username> /p:<password> /v:$target:3389 \
  /cert:ignore /size:1920x1080 +clipboard +drives
```

Pass-the-Hash

```sh
xfreerdp /u:<username> /pth:NTHASH /v:$target /cert:ignore
```

Dynamic resolution

```sh
xfreerdp /u: /p:<password> /v:$target /dynamic-resolution
```
<!-- }}} -->

<!-- }}} -->

<!-- rdesktop {{{-->
### rdesktop

[rdesktop](https://linux.die.net/man/1/rdesktop) —
Remote Desktop Protocol client 

Basic connection

```sh
rdesktop $target
```

With credentials

```sh
rdesktop -u <username> -p <password> $target
```

Full screen

```sh
rdesktop -u <username> $target -f
```

Specific resolution

```sh
rdesktop -u <username> $target -g 1920x1080
```
<!-- }}} -->

___
<!-- }}} -->

<!-- Windows {{{-->
## Windows

<!-- mstsc {{{-->
### mstsc

[mstsc](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc) —
Creates connections to Remote Desktop Session Host servers
or other remote computers

Basic connection

```sh
mstsc /v:$target
```

With specific port

```sh
mstsc /v:$target:3389
```

Full screen mode

```sh
mstsc /v:$target /f
```

Admin mode

```sh
mstsc /v:$target /admin
```

Save connection settings

```sh
mstsc /v:$target /save:connection.rdp
```

<!-- }}} -->

___
<!-- }}} -->

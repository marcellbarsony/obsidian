---
id: xfreerdp
aliases: []
tags: []
---

# Xfreerdp

[xfreerdp](https://linux.die.net/man/1/xfreerdp) —
FreeRDP X11 client

___

<!-- Install {{{-->
## Install

Install

```sh
sudo apt install freerdp3-x11
```

___
<!-- }}} -->

<!-- Connect {{{-->
## Connect

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

___
<!-- }}} -->

<!-- Pass-the-Hash {{{-->
## Pass-the-Hash

```sh
xfreerdp /u:<administrator> /pth:<NTHASH> /v:$target /cert:ignore
```
___
<!-- }}} -->

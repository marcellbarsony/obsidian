---
id: Connect
aliases: []
tags:
  - Microsoft/Windows/Connect
links: "[[Windows]]"
---

# Connect

___

<!-- Terminal {{{-->
## Terminal

[PSExec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
(*[[Impacket]]*) — Connect from a Linux host to a Windows target with credentials

```sh
impacket-psexec <user>@$target
```

```sh
psexec.py <user>@$target
```

___
<!-- }}} -->

<!-- RDP {{{-->
## RDP

[xfreerdp](https://linux.die.net/man/1/xfreerdp) —
FreeRDP X11 client

```sh
xfreerdp3 /v:$target /u:<user> /p:'<password>' [/dynamic-resolution]
```

___
<!-- }}} -->

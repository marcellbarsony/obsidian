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

> [!tip]
>
> TCP VPN connection recommended

[xfreerdp](https://linux.die.net/man/1/xfreerdp) —
FreeRDP X11 client

```sh
xfreerdp3 /v:$target /u:<user> /p:'<password>' [/dynamic-resolution]
```

[rdesktop](https://linux.die.net/man/1/rdesktop) —
Remote Desktop Protocol client

```sh
rdesktop -u <user> -p '<password>' $target[:port]
```

[remmina](https://manpages.debian.org/unstable/remmina/remmina.1.en.html) —
Remmina GTK+ Remote Desktop Client

```sh
sudo apt install remmina
```

```sh
remmina -c rdp://<user>:<password>@$target
```

___
<!-- }}} -->

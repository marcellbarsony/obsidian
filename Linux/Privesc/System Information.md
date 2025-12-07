---
id: System Information
aliases: []
tags:
  - Linux/Privesc/System-Information
links: "[[Privesc]]"
---

# System Information

___


<!-- Hostname {{{-->
## Hostname

Identify hostname/domainname

[hostname](https://linux.die.net/man/1/hostname) —
Show or set the system's host name

```sh
hostname
```

[domainname](https://linux.die.net/man/1/hostname) —
Show or set the system's NIS/YP domain name

```sh
domainname
```

[dnsdomainname ](https://linux.die.net/man/1/hostname) —
Show the system's DNS domain name

```sh
dnsdomainname
```

[nisdomainname](https://linux.die.net/man/1/hostname) —
Show or set system's NIS/YP domain name

```sh
nisdomainname
```

[ypdomainname](https://linux.die.net/man/1/hostname) —
Show or set the system's NIS/YP domain name 

```sh
ypdomainname
```

___
<!-- }}} -->

<!-- OS Version {{{-->
## OS Version

OS Version from environment variables

```sh
cat /etc/os-release 2>/dev/null
```

List OS version

```sh
(cat /proc/version || uname -a ) 2>/dev/null
```

```sh
lsb_release -a 2>/dev/null # deprecated
```

___
<!-- }}} -->

<!-- Hardware Information {{{-->
## Hardware Information

<!-- CPU {{{-->
### CPU

[lscpu](https://linux.die.net/man/1/lscpu) —
Display information about the CPU architecture

```sh
lscpu
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> lscpl
> ```
> ```sh
> Architecture:                    x86_64
> CPU op-mode(s):                  32-bit, 64-bit
> Byte Order:                      Little Endian
> Address sizes:                   43 bits physical, 48 bits virtual
> CPU(s):                          2
> On-line CPU(s) list:             0,1
> Thread(s) per core:              1
> Core(s) per socket:              2
> Socket(s):                       1
> NUMA node(s):                    1
> Vendor ID:                       AuthenticAMD
> CPU family:                      23
> Model:                           49
> Model name:                      AMD EPYC 7302P 16-Core Processor
> Stepping:                        0
> CPU MHz:                         2994.375
> BogoMIPS:                        5988.75
> Hypervisor vendor:               VMware
>
> <SNIP>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Printer {{{-->
### Printer

[lpstat](https://man7.org/linux/man-pages/man1/lpstat.1.html) —
Print cups status information

```sh
lpstat -a 2>/dev/null
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Login Shells {{{-->
## Login Shells

Enumerate Login Shells

```sh
cat /etc/shells
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> MarciPwns@htb[/htb]$ cat /etc/shells
> ```
>
> ```sh
> # /etc/shells: valid login shells
> /bin/sh
> /bin/bash
> /usr/bin/bash
> /bin/rbash
> /usr/bin/rbash
> /bin/dash
> /usr/bin/dash
> /usr/bin/tmux
> /usr/bin/screen
> ```
<!-- }}} -->

___
<!-- }}}} -->

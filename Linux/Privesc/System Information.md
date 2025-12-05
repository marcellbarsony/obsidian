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

<!-- Kernel Exploits {{{-->
## Kernel Exploits

If a host is not being maintained and running an unpatched
or old operating system, potential kernel vulnerabilities may exist

<!-- Kernel Version {{{-->
### Kernel Version

Check kernel version

```sh
uname -r
```

```sh
uname -a
```

```sh
cat /proc/version
```

```sh
cat /etc/os-release
```

<!-- }}} -->

<!-- Public Exploits {{{-->
### Public Exploits

[[SearchSploit]] — Search for public kernel exploits

```sh
searchsploit "Linux Kernel"
```

<!-- Tip - Kernel Exploits Lists {{{-->
> [!tip]- Kernel Exploits Lists
>
> - [GitHub - Kernel exploits](https://github.com/lucyoa/kernel-exploits)
> - [GitLab - Exloit DB](https://gitlab.com/exploit-database/exploitdb-bin-sploits)
<!-- }}} -->

<!-- DirtyCow {{{-->
#### DirtyCow

[CVE-2016-5195](https://nvd.nist.gov/vuln/detail/cve-2016-5195)
Linux Kernel <= `3.19.0`-`73.8`

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Exploit DB - Dirty COW Linux Kernel 2.6.22 < 3.9](https://www.exploit-db.com/exploits/40839)
<!-- }}} -->

```sh
# Make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

<!-- }}} -->

<!-- DirtyPipe {{{-->
#### DirtyPipe

A flaw (*[CVE-2022-0847](https://nvd.nist.gov/vuln/detail/cve-2022-0847)*)
was found in the way the "flags" member of the new pipe buffer structure
was lacking proper initialization in `copy_page_to_iter_pipe`
and `push_pipe` functions in the Linux kernel and could thus contain
stale values.
An unprivileged local user could use this flaw to write to pages
in the page cache backed by read only files and as such
escalate their privileges on the system.

> [!todo]

<!-- }}} -->

<!-- PwnKit {{{-->
#### PwnKit

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/cve-2021-4034)

> [!todo]

<!-- }}} -->

<!-- }}} -->

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

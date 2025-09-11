---
id: System Information
aliases: []
tags:
  - Linux/Privesc/System-Information
links: "[[Privesc]]"
---

# System Information

## PATH

If there is any folder inside the PATH variable with **write permissions**,
it may be possible to hijack some libraries or binaries.

```sh
echo $PATH
```

Automated script

```sh
echo $PATH | tr ':' '\n' | while read dir; do [ -d "$dir" ] && [ -w "$dir" ] && echo "$dir has write permissions"; done
```

## Kernel Exploits

If a host is not being maintained and running an unpatched or old operating
system, potential kernel vulnerabilities may exist.

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

Identify hostname

```sh
hostname
```

### Public Exploits

Search for public kernel exploits

```sh
searchsploit "Linux Kernel"
```

List of vulnerable kernel exploits

- [GitHub - Kernel exploits](https://github.com/lucyoa/kernel-exploits)
- [GitLab - Exloit DB](https://gitlab.com/exploit-database/exploitdb-bin-sploits)

#### DirtyCow (CVE-2016-5195)

Linux Privesc - Linux Kernel <= 3.19.0-73.8

- [Exploit DB - Dirty COW Linux Kernel 2.6.22 < 3.9](https://www.exploit-db.com/exploits/40839)

```sh
# Make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

#### DirtyPipe (CVE-2022-0847)

A flaw was found in the way the "flags" member of the new pipe buffer structure
was lacking proper initialization in `copy_page_to_iter_pipe` and push_pipe
functions in the Linux kernel and could thus contain stale values.
An unprivileged local user could use this flaw to write to pages in the page
cache backed by read only files and as such escalate their privileges on the
system.

- [NVD - CVE-2022-0847](https://nvd.nist.gov/vuln/detail/cve-2022-0847)

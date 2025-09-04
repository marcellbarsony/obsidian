# System info

## OS info

Get OS information

```sh
(cat /proc/version || uname -a ) 2>/dev/null
cat /etc/os-release 2>/dev/null # universal on modern systems
lsb_release -a 2>/dev/null # old, not by default on many systems
```

## PATH

If there is any folder inside the PATH variable with **write permissions**,
it may be possible to hijack some libraries or binaries.

```sh
echo $PATH
```

## Environment variables

Check environment variables for passwords and API keys

```sh
(env || set) 2>/dev/null
```

## Kernel exploits

Check kernel version

```sh
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

List of vulnerable kernel exploits
- [GitHub - Kernel exploits](https://github.com/lucyoa/kernel-exploits)
- [GitLab - Exloit DB](https://gitlab.com/exploit-database/exploitdb-bin-sploits)

### DirtyCow (CVE-2016-5195)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```sh
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

## Drives

### Mounted drives

```sh
lsblk
```

### Fstab

Check fstab files for credentials

```sh
cat /etc/fstab
```

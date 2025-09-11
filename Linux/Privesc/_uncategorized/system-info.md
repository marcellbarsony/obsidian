---
id: system-info
aliases: []
tags: []
---


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

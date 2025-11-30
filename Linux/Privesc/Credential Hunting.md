---
id: Credential Hunting
aliases: []
tags:
  - Linux/Privesc/Credential-Hunting
---

# Credential Hunting

Search for exposed credentials in configuration files, log files,
and user history files

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Password Hunting – Linux Privilege Escalation](https://juggernaut-sec.com/password-hunting-lpe/)
<!-- }}} -->

___

<!-- Directories {{{-->
## Directories

<!-- Current Directory {{{-->
### Current Directory

Check current (*any*) directory for [[Secrets]]

```sh
cat * | grep -i passw*
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' . -R
```

<!-- }}} -->

<!-- Home Directory {{{-->
### Home Directory

Check `home` directory for [[Secrets]]

```sh
grep -iE 'user|password' ~/ -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' ~/ -R
```

<!-- }}} -->

<!-- Root Directory {{{-->
### Root Directory

Check `/root` directory for [[Secrets]]

```sh
grep -iE 'user|password' /root -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /root -R
```

<!-- }}} -->

<!-- TMP Directory {{{-->
### TMP Directory

List all contents of all temporary directories

```sh
ls -l /tmp /tmp/var /var/tmp /dev/shm
```

Check `/tmp` directory for [[Secrets]]

```sh
grep -iE 'user|password' /tmp -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /tmp -R
```

Check `/tmp/var` directory for [[Secrets]]

```sh
grep -iE 'user|password' /tmp/var -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /tmp/var -R
```

Check `/var/tmp` directory for [[Secrets]]

```sh
grep -iE 'user|password' /var/tmp -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /var/tmp -R
```

Check `/dev/shm` directory for [[Secrets]]

```sh
grep -iE 'user|password' /dev/shm -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /dev/shm -R
```

<!-- }}} -->

<!-- Web App Root {{{-->
### Web App Root

[[Web Server Root#OS|OS-Specific Root]] (*`/var/www/`*)

```sh
grep -iE 'user|password' /var/www/* -R
```
```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /var/www/* -R
```
```sh
find /var/www/ -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

[[Web Server Root#Web Server|Web Server Application Root]]

```sh
grep -iE 'user|password' <path> -R
```
```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' <path> -R
```
```sh
find <path> -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

[wp-config.php](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/)

```sh
grep 'DB_USER\|DB_PASSWORD' wp-config.php
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Files {{{-->
## Files

<!-- Configuration Files {{{-->
### Configuration Files

Discover Configuration Files in a directory

```sh
find ~ -type f \( -iname "*.conf" -o -iname "*.cfg" -o -iname "*.config" \) 2>/dev/null
```

Discover Configuration Files for [[Secrets]]

```sh
find / -type f \( -iname "*.conf" -o -iname "*.cfg" -o -iname "*.config" \) 2>/dev/null \
 | xargs grep -Ei 'user|username|pass|password|secret|token|api|key' 2>/dev/null
```

<!-- }}} -->

<!-- Fstab {{{-->
### Fstab

[Fstab](https://en.wikipedia.org/wiki/Fstab)
(*File System Table*) file (*`/etc/fstab`*)
can be used to define how disk partitions, various other block devices,
or remote file systems should be mounted into the file system

Enumerate `/etc/fstab` for [[Secrets]]

```sh
grep -Ei 'user=|username=|pass=|password=|secret=|cred' /etc/fstab 2>/dev/null
```

<!-- }}} -->

<!-- Hidden Items {{{-->
### Hidden Items

Discover hidden directories

```sh
find / -type d -name ".*" -ls 2>/dev/null
```

Discover hidden files (*dotfiles*)

```sh
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
```

Discover hidden files for [[Secrets]]

```sh
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null \
 | grep -Ei 'user|username|pass|password|key|secret|token'
```

<!-- }}} -->

<!-- Shell {{{-->
### Shell

Search shell files for [[Secrets]]

<!-- Bash {{{-->
#### Bash

Bash history

```sh
cat ~/.bash_history | grep -iE 'user|password'
```

```sh
cat ~/.bash_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

Bash configuration

```sh
cat ~/.bashrc | grep -iE 'user|password'
```

```sh
cat ~/.bashrc | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

Bash env

```sh
cat ~/.bashenv | grep -iE 'user|password'
```

```sh
cat ~/.bashenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

<!-- }}} -->

<!-- Zsh {{{-->
#### Zsh

Zsh history

```sh
cat ~/.zsh_history | grep -iE 'user|password'
```

```sh
cat ~/.zsh_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

Zsh configuration

```sh
cat ~/.zshrc | grep -iE 'user|password'
```

```sh
cat ~/.zshrc | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

Zsh env

```sh
cat ~/.zshenv | grep -iE 'user|password'
```

```sh
cat ~/.zshenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Environment Variables {{{-->
## Environment Variables

Check Environment Variables for [[Secrets]]

```sh
printenv | grep -iE 'user|password'
```

```sh
printenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

```sh
(env || set) 2>/dev/null
```
___
<!-- }}} -->

<!-- Found Secrets {{{-->
# Found Secrets

| Secret             | Action                                 |
| ------------------ | -------------------------------------- |
| NTLM hash          | Crack it or spray with CME             |
| Password string    | Try RDP, SMB, WinRM                    |
| SSH Key            | Pivot via SSH to other boxes           |
| Database creds     | Try MySQL/MSSQL pivot and xp_cmdshell  |
| Browser creds      | Pivot web apps, internal portals       |
| Wi-Fi key          | Try new wireless pivot                 |
| Sticky Notes/Notes | Decode plaintext secrets               |
| .kdbx (KeePass)    | Hash dump → crack with [[Hashcat]]     |

___
<!-- }}} -->

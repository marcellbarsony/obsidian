---
id: Credential Hunting
aliases: []
tags:
  - Linux/Privesc/Credential-Hunting
---

# Credential Hunting

Search for exposed credentials in configuration files, log files,
and user history files.

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Password Hunting – Linux Privilege Escalation](https://juggernaut-sec.com/password-hunting-lpe/)
<!-- }}} -->

___

<!-- Directory Contents {{{-->
## Directory Contents

### Current Directory

Check current (*any*) directory for [[Secrets]]

```sh
cat * | grep -i passw*
```

### root Directory

Check `/root` directory for [[Secrets]]

```sh
grep -iE 'user|password' /root -R
```
```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /root -R
```

### Home Directory

Check `home` directory for [[Secrets]]

```sh
grep -iE 'user|password' ~/ -R
```
```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' ~/ -R
```
___

<!-- }}} -->

<!-- Shell {{{-->
## Shell

### Bash

Bash history

```sh
cat ~/.bash_history | grep -iE 'user|password'
```
```sh
cat ~/.bash_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

### Zsh

Zsh history

```sh
cat ~/.zsh_history | grep -iE 'user|password'
```
```sh
cat ~/.zsh_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```
___
<!-- }}} -->

<!-- Environment Variables {{{-->
## Environment Variables

Environment Variables

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

<!-- Web App Source Code {{{-->
## Web App Source Code

[[Web Server Root#OS|OS-specific Root]] (*`/var/www/`*)

```sh
grep -iE 'user|password' /var/www/* -R
```
```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /var/www/* -R
```
```sh
find /var/www/ -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

[[Web Server Root#Web Server|Web Server Application Roots]]

```sh
grep -iE 'user|password' <path> -R
```
```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' <path> -R
```
```sh
find <path> -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

___
<!-- }}} -->

<!-- Found Secrets {{{-->
# Found Secrets

| Secret             | Action                                 |
| ------------------ | -------------------------------------- |
| NTLM hash          | Crack it or spray with CME             |
| Password string    | Try RDP, SMB, WinRM immediately        |
| SSH Key            | Pivot via SSH to other boxes           |
| Database creds     | Try MySQL/MSSQL pivot and xp_cmdshell  |
| Browser creds      | Pivot web apps, internal portals       |
| Wi-Fi key          | Try new wireless pivot                 |
| Sticky Notes/Notes | Decode plaintext secrets               |
| .kdbx (KeePass)    | Hash dump → crack with hashcat         |

___
<!-- }}} -->

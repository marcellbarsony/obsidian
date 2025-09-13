---
id: Credential Hunting
aliases: []
tags: []
---

# Credential Hunting

Look for exposed credentials in configuration files, log files, and user history
files.

## root directory

Check `/root` directory for secrets

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /root -R
```

## Home directory

Check `home` directory for secrets

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' ~/ -R
```

<!-- Shell {{{-->
## Shell

### Bash

Bash history

```sh
cat ~/.bash_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

### Zsh

Zsh history

```sh
cat ~/.zsh_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```
<!-- }}} -->

<!-- Environment Variables {{{-->
## Environment Variables

Environment Variables

```sh
printenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

```sh
(env || set) 2>/dev/null
```
<!-- }}} -->

<!-- Web App Source Code {{{-->
## Web App Source Code

Web Server root (`/var/www/`)

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /var/www/* -R
```

```sh
find /var/www/ -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```
<!-- }}} -->

# Found Secrets

| Secret             | Action                                 |
| ------------------ | -------------------------------------- |
| NTLM hash          | Crack it or spray with CME             |
| Password string    | Try RDP, SMB, WinRM immediately        |
| SSH Key            | Pivot SSH into other boxes             |
| Database creds     | Try MySQL/MSSQL pivot and xp_cmdshell  |
| Browser creds      | Pivot web apps, internal portals       |
| Wi-Fi key          | Try new wireless pivot                 |
| Sticky Notes/Notes | Decode plaintext secrets               |
| .kdbx (KeePass)    | Hash dump → crack with hashcat         |

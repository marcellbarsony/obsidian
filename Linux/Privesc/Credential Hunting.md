---
id: Credential Hunting
aliases: []
tags:
  - Linux/Privesc/Credential-Hunting
---

# Credential Hunting

Search for exposed credentials in configuration files, log files,
shell files, user history files, etc.

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Password Hunting – Linux Privilege Escalation](https://juggernaut-sec.com/password-hunting-lpe/)
<!-- }}} -->

___

<!-- Directories {{{-->
## Directories

<!-- Current {{{-->
### Current

Check current (*any*) directory for [[Secrets]]

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' . -R
```

<!-- }}} -->

<!-- Home {{{-->
### Home

Check `home` directory for [[Secrets]]

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /home -R
```

<!-- }}} -->

<!-- Log {{{-->
### Log

Check system log directories for [[Secrets]]

Main system logs

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /var/log -R
```

Web server logs

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /var/log/apache2 -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /var/log/httpd -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /var/log/nginx -R
```

<!-- }}} -->

<!-- Root {{{-->
### Root

Check `/root` directory for [[Secrets]]

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /root -R
```

<!-- }}} -->

<!-- TMP {{{-->
### TMP

Check TMP directories for [[Secrets]]

List all contents of all temporary directories

```sh
ls -al /tmp /tmp/var /var/tmp /dev/shm
```

`/tmp`

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /tmp -R
```

`/tmp/var`

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /tmp/var -R
```

`/var/tmp`

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /var/tmp -R
```

`/dev/shm`

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /dev/shm -R
```

<!-- }}} -->

<!-- Web App Root {{{-->
### Web App Root

[[Web Server Root#OS|OS-Specific Root]] (*`/var/www/`*)

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' /var/www/* -R
```

```sh
find /var/www/ -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

[[Web Server Root#Web Server|Web Server Application Root]]

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*' <path> -R
```

```sh
find <path> -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

[wp-config.php](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/)

```sh
grep 'DB_USER\|DB_PASSWORD' wp-config.php
```

```sh
cat /var/wp-config.php | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Files {{{-->
## Files

<!-- Backup {{{-->
### Backup

Discover & Search backup files for [[Secrets]]

```sh
find . -type f \( -iname "*.bak" -o -iname "*.backup" \) 2>/dev/null
```

```sh
find / -type f \( -iname "*.bak" -o -iname "*.backup" \) 2>/dev/null \
 | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|HTB' 2>/dev/null
```

<!-- }}} -->

<!-- Configuration {{{-->
### Configuration

Discover & Search configuration files for [[Secrets]]

```sh
find . -type f \( -iname "*.cfg" -o -iname "*.conf" -o -iname "*.config" -o -iname "*.xml" -o -iname "*.log" -o -iname "*.ini" \) 2>/dev/null
```

```sh
find / ! -path "*/proc/*" -type f \( -iname "*.cfg" -o -iname "*.conf" -o -iname "*.config" -o -iname "*.xml" \) 2>/dev/null \
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|HTB' 2>/dev/null
```

<!-- }}} -->

<!-- Database {{{-->
### Database

Discover & Search database files for [[Secrets]]

```sh
find . -type f \( -iname "*.db" -o -iname "*.sql" -o -iname "*.sqlite" \) 2>/dev/null
```

```sh
find / -type f \( -iname "*.db" -o -iname "*.sql" -o -iname "*.sqlite" \) 2>/dev/null \
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|HTB' 2>/dev/null
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
grep -Ei 'user|username|pass|password|secret|token|api|key|HTB' /etc/fstab 2>/dev/null
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
  | grep -Ei 'user|username|pass|password|key|secret|token|HTB'
```

<!-- }}} -->

<!-- History {{{-->
### History

Discover & Search history files for [[Secrets]]

```sh
find / -type f \( -name '*_hist' -o -name '*_history' \) -exec ls -l {} \; 2>/dev/null
```

```sh
find / -type f \( -name '*_hist' -o -name '*_history' \) -exec ls -l {} \; 2>/dev/null \
  | grep -Ei 'user|username|pass|password|key|secret|token|HTB'
```

<!-- }}} -->

<!-- Log {{{-->
### Log

Search log files for [[Secrets]]

Core system logs

```sh
cat /var/log/syslog | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

```sh
cat /var/log/messages | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

Authentication logs

```sh
cat /var/log/auth.log | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

Security logs

```sh
cat /var/log/secure.log | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

Kernel logs

```sh
cat /var/log/secure.log | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

<!-- }}} -->

<!-- Scripts {{{-->
### Scripts

Discover & Search for scripts for [[Secrets]]

[[PHP]]

```sh
find / -type f \( -iname "*.php" -o -iname "*.php5" -o -iname "*.php7" -o -iname "*.php8" \) 2>/dev/null \
  | grep -Ev "src|snap|share"
```

```sh
find / -type f \( -iname "*.php" -o -iname "*.php5" -o -iname "*.php7" -o -iname "*.php8" \) 2>/dev/null \
  | grep -Ev "src|snap|share" \
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|HTB' 2>/dev/null
```

[[Python]]

```sh
find / -type f \( -iname "*.py" -o -iname "*.pyw"\) 2>/dev/null \
  | grep -Ev "src|snap|share"
```

```sh
find / -type f \( -iname "*.py" -o -iname "*.pyw"\) 2>/dev/null \
  | grep -Ev "src|snap|share" \
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|HTB' 2>/dev/null
```

[[Shell]]

```sh
find / -type f \( -iname "*.sh" \) 2>/dev/null \
  | grep -Ev "src|snap|share"
```

```sh
find / -type f \( -iname "*.sh" \) 2>/dev/null \
  | grep -Ev "src|snap|share" \
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|HTB' 2>/dev/null
```


<!-- }}} -->

<!-- Shell {{{-->
### Shell

Search shell files for [[Secrets]]

<!-- Bash {{{-->
#### Bash

Bash history

```sh
cat ~/.bash_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

Bash configuration

```sh
cat ~/.bashrc | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

Bash env

```sh
cat ~/.bashenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

<!-- }}} -->

<!-- Zsh {{{-->
#### Zsh

Zsh history

```sh
cat ~/.zsh_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

Zsh configuration

```sh
cat ~/.zshrc | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

Zsh env

```sh
cat ~/.zshenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
```

<!-- }}} -->

<!-- }}} -->

<!-- Text {{{-->
### Text

Discover & Search text files for [[Secrets]]

```sh
find . -type f \( -iname "*.txt" -o -iname "*.backup" \) 2>/dev/null
```

```sh
find / -type f \( -iname "*.bak" -o -iname "*.backup" \) 2>/dev/null \
| xargs grep -Ei 'user|username|pass|password|secret|token|api|key|HTB' 2>/dev/null
```

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
printenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|HTB.*'
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

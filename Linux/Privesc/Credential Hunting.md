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

<!-- Tip {{{-->
> [!tip]
>
> [[Found Secrets]]
>
<!-- }}} -->


___

<!-- Directories {{{-->
## Directories

<!-- Current {{{-->
### Current

Check current (*any*) directory for [[Secrets]]

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' . -R
```

<!-- }}} -->

<!-- Home {{{-->
### Home

Check `home` directory for [[Secrets]]

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /home -R
```

<!-- }}} -->

<!-- Log {{{-->
### Log

Check system log directories for [[Secrets]]

Main system logs

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /var/log -R
```

Web server logs

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /var/log/apache2 -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /var/log/httpd -R
```

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /var/log/nginx -R
```

<!-- }}} -->

<!-- Root {{{-->
### Root

Check `/root` directory for [[Secrets]]

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /root -R
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
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /tmp -R
```

`/tmp/var`

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /tmp/var -R
```

`/var/tmp`

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /var/tmp -R
```

`/dev/shm`

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /dev/shm -R
```

<!-- }}} -->

<!-- Web App Root {{{-->
### Web App Root

[[Web Server Root#OS|OS-Specific Root]] (*`/var/www/`*)

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' /var/www/* -R
```

```sh
find /var/www/ -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

[[Web Server Root#Web Server|Web Server Application Root]]

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' <path> -R
```

```sh
find <path> -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

[wp-config.php](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/)

```sh
grep 'DB_USER\|DB_PASSWORD' wp-config.php
```

```sh
cat /var/wp-config.php | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
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
 | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' 2>/dev/null
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
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' 2>/dev/null
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
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' 2>/dev/null
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
grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' /etc/fstab 2>/dev/null
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
  | grep -Ei 'user|username|pass|password|key|secret|token|flag|htb'
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
  | grep -Ei 'user|username|pass|password|key|secret|token|flag|htb'
```

<!-- }}} -->

<!-- Log {{{-->
### Log

Search log files for [[Secrets]]

Core system logs

```sh
cat /var/log/syslog | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

```sh
cat /var/log/messages | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

Authentication logs

```sh
cat /var/log/auth.log | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

Security logs

```sh
cat /var/log/secure.log | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

Kernel logs

```sh
cat /var/log/secure.log | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
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
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' 2>/dev/null
```

[[python]]

```sh
find / -type f \( -iname "*.py" -o -iname "*.pyw"\) 2>/dev/null \
  | grep -Ev "src|snap|share"
```

```sh
find / -type f \( -iname "*.py" -o -iname "*.pyw"\) 2>/dev/null \
  | grep -Ev "src|snap|share" \
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' 2>/dev/null
```

[[Shell]]

```sh
find / -type f \( -iname "*.sh" \) 2>/dev/null \
  | grep -Ev "src|snap|share"
```

```sh
find / -type f \( -iname "*.sh" \) 2>/dev/null \
  | grep -Ev "src|snap|share" \
  | xargs grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' 2>/dev/null
```


<!-- }}} -->

<!-- Shell {{{-->
### Shell

Search shell files for [[Secrets]]

<!-- Bash {{{-->
#### Bash

Bash history

```sh
cat ~/.bash_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

Bash configuration

```sh
cat ~/.bashrc | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

Bash env

```sh
cat ~/.bashenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

<!-- }}} -->

<!-- Zsh {{{-->
#### Zsh

Zsh history

```sh
cat ~/.zsh_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

Zsh configuration

```sh
cat ~/.zshrc | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

Zsh env

```sh
cat ~/.zshenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
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
| xargs grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' 2>/dev/null
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
printenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*'
```

```sh
(env || set) 2>/dev/null
```

<!-- Tip {{{-->
> [!tip]-
>
> ```sh
> set
> ```
>
> ```sh
> env
> ```
>
> ```sh
> printenv
> ```
>
> ```sh
> cat /proc/$$/environ
> ```
>
> ```sh
> cat /proc/`python -c "import os; print(os.getppid())"`/environ
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Clipboard {{{-->
## Clipboard

Enumerate the clipboard

```sh
if [ `which xclip 2>/dev/null` ]; then
    echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
    echo "Highlighted text: "`xclip -o 2>/dev/null`
  elif [ `which xsel 2>/dev/null` ]; then
    echo "Clipboard: "`xsel -ob 2>/dev/null`
    echo "Highlighted text: "`xsel -o 2>/dev/null`
  else echo "Not found xsel and xclip"
  fi
```

___
<!-- }}} -->

<!-- Keys {{{-->
## Keys

Find [PGP Keys](https://en.wikipedia.org/wiki/Pretty_Good_Privacy)

```sh
gpg --list-keys 2>/dev/null
```

```sh
gpg --list-secret-keys --keyid-format=long
```

___
<!-- }}} -->

<!-- Processes {{{-->
## Processes

Search [[Processes]] for [[Secrets]]

```sh
ps -ef | grep -Ei 'user|username|pass|password|secret|token|api|key|flag|htb' | grep -v grep
```

```sh
ps -eo pid,user,cmd --no-header \
  | grep -IaiE 'user|username|pass|password|secret|token|api|key|flag|htb'
```

<!-- Info {{{-->
> [!info]-
>
> - `a`: Treat binary as text
> - `E`: Extended regex
> - `i`: Ignore case
> - `I`: Ignore binary
<!-- }}} -->

___
<!-- }}} -->

